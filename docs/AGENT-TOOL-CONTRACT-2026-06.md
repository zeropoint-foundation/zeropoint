# Agent / Tool Integration Tier Contract — What Agents and Tools Must, May, and Must Not Do

*Dated 2026-06. The runtime-neutral contract between the Agent/tool
integration tier and the substrate. Names which affordances an agent
implementation and a tool implementation MUST have, which they MAY have,
and which they MUST NOT have, so that affordance gaps are classifiable as
degradations vs disqualifications vs correct postures.*

*Updates to this doc are architectural acts and should be treated as such.*

---

## 1. What this doc is

This is the Agent/tool integration tier contract — the operational
complement to `docs/design/governed-agent-runtime.md` (GAR) at the
agent-substrate and tool-substrate integration surfaces. Where the GAR
is design-spec-shaped — describing the five mediation surfaces, the
containment model, the canonicalization lifecycle, and IronClaw's
specific integration points — this document extracts the affordance
partition: what makes an agent or a tool conformant to the substrate's
governance model, runtime-neutral and implementation-plural.

The two are complementary. The GAR describes the IronClaw-specific
runtime in depth and gives the architectural rationale for each
governance surface. This contract names the tier-scoped Required,
Optional, and Forbidden affordances that any agent — IronClaw, Hermes,
a Python orchestrator, a TypeScript agent, a Claude Code instance — and
any tool — a Rust WASM crate, an AssemblyScript extension, a native
subprocess — must satisfy to participate in the substrate's governance
domain.

This document is the spoke for Tier 6 in `SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md`.
Agents and tools occupy one tier because they are tightly coupled: agents
invoke tools through the gate; tools are the capabilities agents act through;
the gate is the seam between them. The contract partitions each category
internally into agent-side and tool-side affordances, but one tier is
the right shape for the same reason one receipt triple covers intent,
policy, and execution — the parts are inseparable.

---

## 2. The category statement

Agents are actors that operate on behalf of operators under chain-anchored
delegation. They receive a scoped capability grant, use the gate to request
tool invocations, emit receipts for every action, and are bounded by the
lease windows and authority the operator's chain records for them. Tools
are the substrate-exposed capabilities that agents invoke — each a
canonicalized, side-effect-producing unit whose execution is gated,
receipted, and bounded by its declared capability scope. Neither holds
authority on its own. Authority flows from Genesis through the chain,
through the gate, to whatever action is about to happen.

The cockpit-OS framing from Architecture §4b applies with full force at
this tier: agents are not the substrate, they are tenants of it. The
substrate is the operator's runtime for coherent agent authority; the
agent is what runs inside that runtime under the operator's delegation.
A governed agent does not decide what it can do — it discovers, through
the gate's evaluation of its capability grants, what the current chain
state authorizes, and it acts within that envelope. An agent that
maintains its own authority claims, holds its own capability ledger
across sessions, or bypasses the gate to directly invoke side effects has
stopped being a governed tenant and started being an authority node —
exactly the structural failure Principles 1 and 3 exist to prevent.

The WASM trust boundary is the runtime enforcement mechanism for the
tool tier. WASM tools run in a sandbox where every ambient capability
must be explicitly provided by a host function; the sandbox does not
confer authority, it withdraws it. This is not a Forbidden affordance —
it is the substrate's enforcement primitive for the principle that tools
must not hold ambient authority. A tool compiled to WASM and constrained
to declared host functions is more conformant than a native binary with
ambient filesystem and network access, not less. The Forbidden affordances
for the tool tier name uses that escape the WASM boundary or that escape
gate mediation — not WASM-having-state in general.

---

## 3. Required affordances

An implementation lacking any agent-side Required affordance cannot
participate as a governed agent. An implementation lacking any tool-side
Required affordance cannot participate as a governed tool. The fallback
when the Agent/tool tier is absent is for the operator to interact with
the substrate directly via CLI verbs and for no LLM-backed or
autonomous execution to occur — a real capability degradation but no
correctness implication for chain integrity or gate enforcement.

### Agent-side

**1. Operate under a chain-anchored canonicalized identity.** An agent
must have a `agent:canonicalized` receipt on the audit chain before
emitting any governed receipts or invoking the gate. The
canonicalization receipt establishes the agent's Year Zero: its content
hash at the time of operator recognition, a parent reference linking it
to the canonicalizing authority, and the chain position from which all
subsequent agent receipts derive. An agent process that has not been
canonicalized is invisible to the trust system — the gate will not
evaluate its requests because it has no canonical presence to evaluate
against. This is the canonicalization invariant from GAR §3.4: nothing
executes in a governed context without a canon.

**2. Request all capability invocations through the gate.** Every agent
action that produces a substrate side effect — tool call, memory write,
subprocess spawn, inference request, routine scheduling — must be
requested through the gate before the effect occurs. The gate evaluates
the request against the current capability grants in force for this
agent and session, applies constitutional rules, and either produces a
`gate.tool_call.allowed` receipt (execution proceeds) or a
`gate.tool_call.blocked` receipt (execution does not proceed, the
receipt chain-anchors the denial). The agent surfaces the gate's
decision to the operator when the action is denial-worthy; it does not
circumvent the decision. **P1** (the receipt from the gate is the
structural attestation that the action was authorized), **P3** (no
agent-internal authority substitutes for the gate's chain-derived
evaluation).

**3. Carry a delegation-scoped identity on each gate request.** Each
request to the gate must carry the agent's identity material — in the
current implementation, a `ZP-Sig v1` envelope signed with the agent's
Genesis-derived or delegation-issued key, as defined in
`crates/zp-gate-envelope`. The envelope binds the request to the
specific method, path, and body via BLAKE3, enforces a drift window via
`ts`, and defeats replay within the window via `nonce`. An agent that
sends gate requests without identity material is sending requests the
gate cannot authenticate; the gate will reject them as unauthenticatable
rather than produce a permissive default.

**4. Declare capability needs before or at invocation time.** The agent
must be able to express what capabilities a proposed action requires so
the gate can evaluate whether the current delegation grants cover it.
In MCP-tenancy mode, this is the tool call's named parameters and tool
identifier; in trait-integration mode, this is the structured
`LoopOutcome` carrying the pending action's capability claims. The gate
cannot evaluate against an opaque action. An agent that does not declare
its capability needs structurally cannot receive a valid gate receipt
because the gate has no claims to evaluate.

**5. Respect capability scope and lease windows.** An agent must not
attempt invocations outside the scope or after the expiry of the grants
the operator has issued for it. Gate evaluation enforces this
structurally — a request outside scope produces a blocked receipt — but
an agent that floods the gate with requests it knows are outside scope
is using gate evaluation as a workaround for the absence of self-
governance. Conformant agents derive their understanding of what they
can currently request from the chain state and restrict themselves
accordingly; the gate is the authoritative boundary, not a retry target.

**6. Surface results and gate decisions through substrate-authorized
channels.** Every tool execution result, gate decision, memory write
outcome, and inference response that the agent acts on must flow back
through the substrate's audit surface — a receipt, a cockpit event, an
approved channel return value. Agents must not silently discard gate
denials, silently suppress execution receipts, or act on results that
were not themselves chain-anchored. **P1:** an action whose result
exists in the agent's session context but not in the chain has produced
a gap between the substrate's account of reality and reality itself.

### Tool-side

**1. Register through the gate envelope before accepting execution.**
A tool must be reachable through the substrate's gate — either as a
host function exposed via the WASM component model, as an MCP tool
endpoint declared in the agent's tool registry, or through an equivalent
bounded dispatch interface. The gate must be able to reach the tool by
name, evaluate whether the requesting agent holds a current capability
grant for it, and either proceed or block before any execution occurs.
A tool that can be invoked without a gate-mediated evaluation is not a
governed tool regardless of what it does with its inputs.

**2. Carry a chain-anchored canonicalized identity.** A tool must have
a `tool:canonicalized` receipt on the audit chain, anchored to the agent
that runs it, before accepting dispatch. The canonicalization receipt
binds the tool's content hash at the time of operator recognition to
the governance chain. If the tool binary changes after canonicalization,
the hash diverges — the gate detects the discrepancy and blocks dispatch.
This is tamper evidence by construction, not by monitoring. The
canonicalization invariant applies to tools as it does to agents: an
uncanonicalized tool cannot be dispatched.

**3. Declare side effects and required capabilities in machine-readable
form.** A tool must declare what ambient capabilities it needs to
execute — network domains, filesystem paths, subprocess authority,
credential classes — before or at canonicalization time, in a schema the
gate can inspect. The WASM capability model uses `capabilities.json`
with explicit endpoint allowlists and per-capability flags; MCP tools
declare their parameter schemas; native tools require an equivalent
manifest. The gate evaluates the tool's capability declaration against
the current delegation grants; a tool whose declared capabilities exceed
what the operator has granted for this agent cannot be dispatched. A
tool whose declarations are empty or unreadable is unclassifiable by the
gate and fails closed.

**4. Operate within a bounded execution surface that prevents ambient
authority.** The tool must execute in an environment where ambient
capabilities not declared at canonicalization time are unavailable — not
merely discouraged. The WASM sandbox provides this structurally for
compiled-to-WASM tools: the only capabilities available inside the
sandbox are those the host explicitly exposes via host functions.
Equivalent enforcement for native tools requires OS-level sandboxing
(`sandbox-exec`, seccomp/bubblewrap, or a dedicated subprocess container)
that constrains the tool's ambient access to match its declaration.
The enforcement mechanism varies by runtime; the invariant — no ambient
access to capabilities not declared and gate-granted — does not.

**5. Produce structured results that can be canonicalized into a receipt.**
A tool must return results in a shape the substrate can canonicalize —
structured data that maps to the receipt type system without a lossy
transformation. If the tool's output cannot be canonicalized into a
receipt, the execution cannot be chain-anchored, and the action falls
into the gap between what happened in the world and what the chain
records. Tools that produce unstructured or opaque results (raw binary
blobs, uncategorized text) must wrap their output in a structured
container that the receipt layer can hash, type, and sign.

**6. Honor the gate's pre-evaluation decision unconditionally.** If the
gate produces a `gate.tool_call.blocked` receipt for a request, the
tool must not execute. This sounds redundant — if the gate blocks the
request before the tool receives it, the tool has no opportunity to
execute. It is not redundant: in some integration shapes (MCP-server
mode, trait-based integration) the tool may be reachable through paths
that precede gate evaluation. A conformant tool implementation does not
provide those alternate paths. **P1:** execution without a gate receipt
produces an action without chain-anchored authorization.

---

## 4. Optional affordances

Each optional affordance improves capability or operator experience
without affecting chain correctness, gate integrity, or canonicalization
validity.

### Agent-side

**LLM-backed, deterministic, or human-in-the-loop variants.** The
agent's cognition model is implementation-defined. IronClaw is LLM-
backed with seven provider adapters; a future conformant agent could be
deterministic (a rule-engine executor), human-in-the-loop (a tool that
pauses for operator confirmation at every step), or a hybrid. The
governance model does not require any particular cognition architecture.
Reasoning attestation (GAR §5.5) is stronger for local models that
expose their full generation trace; it degrades gracefully to observed-
only attestation for remote API backends that return only final outputs.
The attenuation is a capability degradation, not a correctness failure.

**Multi-turn planning, tool-selection heuristics, and sub-agent
orchestration.** An agent may plan across multiple turns, use heuristics
to select among available tools, or delegate sub-tasks to child agents
under narrowed capability grants. Each sub-agent invocation and each
delegated action requires its own gate evaluation; the planning layer
above them does not require one. Multi-agent orchestration is optional;
each participating agent must individually satisfy the Required affordances.

**Session-bounded context persistence.** An agent may maintain within-
session context — conversation history, intermediate reasoning steps,
working memory accumulated during a run — as long as this context does
not cross the session boundary outside the chain. The chain is the durable
record; the session context is the ephemeral working surface. Without
this affordance an agent has no continuity within a task; with it the
agent can maintain coherent multi-turn execution. The boundary is the
session: context that persists across sessions is chain-mediated or
it does not exist.

**Proactive gate querying before high-risk actions.** An agent may query
the gate before attempting an action to discover whether it would be
allowed, without committing to the attempt. This is the structural
enforcement of the MCP-tenancy design principle from GAR §3.1.1: "the
agent can plan accordingly — query the gate before attempting a risky
action." Without this affordance the agent learns of a denial only by
attempting the action; with it the agent can adapt before committing.

### Tool-side

**Performance optimizations on pure computations.** A tool may cache
results for computationally expensive pure functions — operations whose
output is determined entirely by their inputs with no side effects —
as a performance optimization, provided the cache does not persist beyond
the process lifetime and does not store operator-derived data. A pure
hash verification, a local text transformation, a static schema
validation are candidates. Operations with external side effects are
never candidates for silent caching. Without this affordance every pure
invocation pays full compute cost; with it the tool is faster, not
less correct.

**Multiple language implementations of the same declared semantics.**
A tool may be implemented in any language that compiles to a conformant
WASM module or provides an equivalent bounded execution surface — Rust,
AssemblyScript, Go, C++, or any other WASM-capable language. The
canonical identity anchored by the `tool:canonicalized` receipt is the
content hash of the specific implementation; different-language
implementations of the same semantic function are distinct canonical
identities. Without this affordance the tool vocabulary is Rust-only;
with it, adopters can contribute tools in whatever language suits their
capability.

**Content-blind operational telemetry.** A tool may emit metrics about
its own execution performance — latency, error rates, memory usage,
invocation counts — without emitting receipt contents or operator-
derived data. This is operationally useful for capacity planning and
degradation detection. Without this affordance the only tool-performance
visibility is through the substrate's receipt chain; with it, operators
have a faster signal for tool health without requiring chain queries.

**Structured result schemas beyond the receipt minimum.** A tool may
return richer structured data than the receipt layer's minimum
canonicalizable shape — a complex JSON object with sub-arrays, nested
metadata, hierarchical provenance information — as long as the full
result can still be reduced to a canonicalizable receipt. The richer
schema improves the cockpit's ability to render the tool's output
meaningfully. Without this affordance tool results render as opaque
receipt payloads; with it they render as structured workspace artifacts.

---

## 5. Forbidden affordances

The forbidden category names things a technically capable implementation
must not do at this tier. Lacking a forbidden affordance is correct
posture at this tier, not degradation.

### Agent-side

**1. Claiming authority not present in a chain-anchored grant.** An
agent must not fabricate capability grants, assert that it holds
authority the operator's chain does not record, or act as if operator
approval has been given when no gate receipt confirms it. This includes
"optimistic execution" patterns — proceeding with an action under the
assumption that approval is forthcoming — and cross-session authority
reuse — treating a grant from a prior session as still valid when the
chain may have withdrawn it. **P1** (the gate receipt is the structural
attestation; an agent-asserted authorization has no witness), **P2**
(authority is cryptographic lineage, not contextual inference).

**2. Bypassing the gate to invoke side effects directly.** An agent
must not produce a subprocess, write to the filesystem, make a network
call, emit a receipt, or trigger any other side effect through a path
that does not involve a gate evaluation. The gate is the one canonical
path for all governed action (P8); any second path for the same
concern is half-state. This applies regardless of whether the side
effect appears "safe" from the agent's perspective — the agent's
assessment of safety is not a gate receipt. An agent that correctly
routes every action through the gate and whose every action is
chain-anchored has, by construction, no bypassed gate calls. **P1,
P8.**

**3. Acting under another operator's identity within a session.** An
agent session is scoped to the operator authenticated at session
establishment. An agent must not switch the operator identity it
projects for — consulting a different operator's chain, requesting
grants against a different operator's delegation, emitting receipts
under a different operator's authority — without a new authentication
ceremony. **P2** (identity is a cryptographic key, not a conversational
claim), **P3** (switching operator identities within a session creates
an unverifiable attribution: which operator's chain anchors which
action?).

**4. Holding cross-session capability state outside the chain.** An
agent must not maintain a persistent capability ledger — a local record
of what it believes it can currently do — that survives session
boundaries independently of the chain. On the next session, the agent
re-derives its capability scope from the chain's current state, because
that is where the authoritative scope lives. An agent whose cross-
session capability state diverges from the chain will eventually present
its operator with affordances the chain no longer authorizes or suppress
affordances the chain has since granted. **P3** (the cross-session
ledger is a center), **P5** (the chain is the primary mode; the
capability ledger is an inverted store-and-forward).

**5. Claiming successful execution without a corresponding chain
receipt.** An agent must not report to the operator that an action
succeeded, return results to a downstream process, or advance its own
task-completion state on the basis of an execution that did not produce
a chain receipt. An action that happened in reality but not in the
chain did not happen as far as the substrate is concerned — and yet it
did happen in the world. That gap is the failure mode. **P1.**

**6. Self-canonicalizing.** An agent must not assert its own governed
existence by producing a `agent:canonicalized` receipt under its own
signing key. Canonicalization is a governance act performed by the
substrate (or by an explicitly authorized canonicalizing authority) on
behalf of the operator. An agent that issues its own canonicalization
receipt has claimed its own Year Zero without operator ceremony — a
structural contradiction, since the chain's authority flows from
Genesis, not from the entity being canonicalized. **P1** (the
canonicalization receipt must be signed by an authority with chain-
standing over the agent), **P2** (identity is cryptographic lineage
from Genesis, not self-assertion).

### Tool-side

**1. Producing side effects through paths that escape the declared
host-function boundary.** A tool must not invoke ambient capabilities —
filesystem writes, network connections, subprocess spawning, credential
reads — through paths not explicitly exposed by the host at
canonicalization time. This is the WASM trust boundary in operational
terms: the host exposes exactly the capabilities the tool declared; the
tool uses only those. The forbidden thing is a tool *escaping* the
boundary — exploiting a WASM host API not in the capability declaration,
using a shared-memory side channel, or invoking a host function that was
not part of the declared capability set. WASM-having-state and WASM-
executing-computation are foundational, not forbidden; the forbidden
thing is reaching through or around the declared boundary. **P3** (a
tool with ambient authority outside its grant is a center of ungoverned
capability), **P8** (the host-function interface is the one canonical
path for tool-side effects; anything else is a second path for the same
concern).

**2. Persisting state across invocations outside the chain.** A tool
must not maintain persistent state — a database, a local file, an in-
memory global — that accumulates across invocations outside what the
substrate's chain records. Each invocation is scoped: inputs come in,
side effects are declared and executed within the host-function
boundary, structured results come out, the receipt chain-anchors the
entire transaction. A tool that carries forward knowledge from previous
invocations in an unreceipted form has introduced an opaque state
machine that no audit walk can reconstruct. **P3** (persistent cross-
invocation state at the tool tier is a center), **P4** (the state path
that isn't the chain earns its place through no cryptographic
necessity).

**3. Executing without a canonicalized identity.** A tool must not
accept dispatch from the gate or any other caller if it lacks a
`tool:canonicalized` receipt on the chain. The canonicalization invariant
is unconditional: an uncanonicalized tool is invisible to the governance
system. A tool that executes without a canon produces actions that
cannot be attributed to any chain-resident identity — the receipt has
no canonical subject. **P1** (the receipt needs a subject to be
structurally meaningful), **P2** (the tool's identity is its
canonicalization chain, not its process name or invocation context).

**4. Returning non-canonicalizable results.** A tool must not return
results in a form that cannot be reduced to a signed, hash-linked receipt.
Opaque binary blobs, streaming outputs without a terminal structured
summary, results whose size or structure defeats BLAKE3 canonicalization
at the receipt layer — none of these are conformant. If the tool's
natural output shape doesn't canonicalize cleanly, the tool is
responsible for wrapping it. **P1** (if the execution result isn't
chain-anchored, the execution has no substrate-attested outcome), **P4**
(an output format that requires a separate out-of-band record to capture
execution evidence is a duplicate data path that earns its place through
no cryptographic necessity).

**5. Holding signing material or operator-derived secrets beyond
invocation lifetime.** A tool must not retain the operator's keys,
session tokens, credential material, or any other operator-derived secret
past the end of the invocation that received them. Credential injection
at the WASM host boundary — the host injects the credential into the
WASM linear memory at invocation time and the WASM module uses it within
the invocation — is the conformant shape. A WASM tool that writes
received credentials to a declared host-function filesystem path for
use by future invocations has held operator-derived material across
invocation boundaries; the material is now in tool-controlled storage,
not in the vault, and the operator's audit of what holds their secrets
is incomplete. **P1** (operator-derived secrets outside the vault are
material held outside the chain's authority), **P3** (a tool that holds
signing material is a credential center that shouldn't exist at this
tier).

---

## 6. Composition with principles

The contract's Required category is shaped primarily by P1 and P6; its
Forbidden category by P1, P2, P3, and P8.

**P1 (signing is gravity) is the load-bearing principle for most of the
Forbidden category.** Every forbidden agent-side entry (1, 2, 5, 6) and
every forbidden tool-side entry (3, 4) traces directly to P1: the chain
receipt is the only structural attestation that an action was authorized,
that an identity is real, that an execution produced an outcome the
substrate can vouch for. An agent that bypasses the gate, a tool that
executes without a canon, a tool that returns non-canonicalizable results
— each produces actions or outcomes without a witness. P1 is why the gap
between "it happened in the world" and "it happened in the chain" is not
a logging gap but an architecture gap.

**P3 (there is no center) justifies the cross-session and state-
persistence forbidden entries.** Agent-side entries 3 and 4 prevent the
agent from becoming a persistent authority node — holding identity claims
across sessions or capability grants that haven't been re-derived from
the chain. Tool-side entries 1, 2, and 5 prevent the tool from becoming
a persistent capability node — holding ambient access, cross-invocation
state, or credential material that the operator's vault should be the
sole authority for. All five are ways an agent or tool could accumulate
authority outside the chain; P3 prohibits centers by construction.

**P2 (identity is a key, not a location) justifies agent-side entries 3
and 6 and tool-side entry 3.** Identity in the substrate is
cryptographic lineage from Genesis, not a process name, a port, or a
conversational claim. An agent that switches operator identities within
a session is claiming that conversational context changes who it is; a
tool without a canonicalization receipt is claiming existence without a
cryptographic anchor; an agent that self-canonicalizes is claiming
authority to establish its own identity. All three are versions of the
same error: confusing operational context with cryptographic identity.

**P8 (one canonical path) justifies agent-side entry 2 and tool-side
entry 1.** The gate is the one canonical path for all governed action.
Any second path for the same concern — a direct API call that skips gate
evaluation, an ambient tool capability that bypasses the host-function
interface — produces half-state: two paths for the same concern that may
disagree on what happened. P8 is why the Forbidden category for this
tier doesn't merely recommend against bypasses; it disqualifies
implementations that provide them.

**P6 (a tool is intent, crystallized) is the structural basis for the
Required affordances.** The verb set is the crystallized form of agent
intent; the gate is the protocol, not a guardrail; tool semantics live
in the receipt structure, not in prose descriptions of what the tool
"does." Required agent affordances 2–4 (gate request, identity envelope,
capability declaration) are what makes intent structurally expressed —
not just conversationally described. Required tool affordances 3 and 5
(capability declaration, canonicalizable results) are what makes the
tool's side effects legible to the governance grammar.

---

## 7. Portability sketches

The contract is runtime-neutral. Conformance is achievable across
substantially different agent architectures and tool execution environments.

**IronClaw as a governed agent (current reference).** A Rust process
integrating with the substrate via the `CockpitProvider` trait, running
under credential injection from the ZP vault, with every tool dispatch
evaluated at `POST /api/v1/gate/tool-call` using a `ZP-Sig v1` envelope.
Canonicalization chain established at launch (`rcpt-genesis → rcpt-cfg-ic
→ rcpt-preflight → rcpt-port → rcpt-launched → rcpt-health`). WASM tools
execute inside Wasmtime with declared capability schemas
(`src/tools/wasm/capabilities.rs`). All Required affordances present for
both agent-side (identity, gate request, capability declaration) and
tool-side (canonicalized identity, WASM boundary, canonicalizable results).
IronClaw is the first conformant tenant; it is not the only one.

**Hermes Agent as a second tenant (Phase 4 roadmap).** A Python process
integrated via subprocess bridge and MCP-server mode rather than trait
injection. The integration shape differs — no `CockpitProvider`, bridge
process handles the language boundary — but the contract surface is
identical: the agent's gate requests carry identity material, capability
grants are evaluated against the chain, every action produces a receipt.
The Required affordances are achievable in Python via the MCP-tenancy
path; the Forbidden affordances apply regardless of implementation
language. Hermes's own memory backend, credential management, and cron
scheduler must either be replaced by substrate equivalents or wrapped at
the governance seams — the canonicalization invariant does not relax for
second tenants.

**Rust WASM tools compiled from `crates/zp-*` (current default tool
runtime).** Tools compiled to WASM modules using the Wasmtime component
model, with capability schemas declaring endpoint allowlists and
per-capability flags. All Required tool affordances are naturally
satisfied: the WASM sandbox enforces the bounded execution surface;
`capabilities.json` provides the machine-readable capability declaration;
Wasmtime's host-function model ensures results flow through a typed
interface the receipt layer can canonicalize. The Forbidden tool
affordances are enforced structurally by the WASM boundary rather than
by discipline.

**AssemblyScript, Go, or C++ WASM tools.** Any language that compiles
to a conformant WASM module and can produce structured results against
the receipt schema is a conformant tool runtime. The WASM component model
provides the host-function interface regardless of the source language.
Required affordances #3 and #4 (capability declaration and bounded
execution surface) are satisfied by the WASM toolchain, not by source
language choice. Conformance is a property of the compiled module's
interaction with the gate, not of the language it was written in.

**Native-process tools via gate envelope (future).** For tools that
cannot be compiled to WASM — tools with hardware dependencies, tools
requiring OS-level APIs not exposable as WASM host functions, tools
where the WASM sandbox overhead is operationally prohibitive — a native-
process variant interfaces with the gate through the envelope protocol
at the process boundary rather than through WASM host functions
internally. The Required tool affordances still apply: the process must
have a canonicalized identity, must declare its capabilities in a gate-
inspectable manifest, and must produce canonicalizable results. The
bounded execution surface (Required #4) is provided by OS-level
sandboxing rather than the WASM runtime. The Forbidden tool affordances
apply equally. The contract does not require WASM; it requires the
invariants that WASM enforces by default.

---

## 8. Autoregressive update triggers

1. **A new agent runtime is adopted.** If the substrate integrates with
   a new agent framework — OpenAI Agents SDK, Claude Agent SDK, a custom
   orchestrator — the portability sketches should be updated. If the new
   framework's integration shape surfaces Required affordances that the
   current contract doesn't name explicitly, revise. If the framework
   structurally cannot satisfy a Required affordance, this is either a
   scope restriction (the framework is out of scope for governed deployment)
   or a contract revision question.

2. **A new tool runtime is adopted.** If the substrate ships support for
   a non-WASM tool sandbox — eBPF-based sandboxing, hardware enclave
   execution, a new process-isolation primitive — the contract should be
   updated to name the new enforcement mechanism and confirm that the
   Required and Forbidden affordances still hold under it.

3. **A Required affordance proves hard to implement portably.** If
   "every agent must carry a ZP-Sig v1 envelope on gate requests" turns
   out to be infeasible for a runtime worth supporting — perhaps because
   the runtime's HTTP client doesn't support custom `Authorization` headers —
   the question is whether to relax the affordance, define a protocol
   extension, or accept the runtime is out of scope.

4. **A Forbidden affordance is proposed for relaxation.** If someone
   proposes "let agents hold a short-lived capability cache across sessions
   for latency reasons," this doc is what the proposal must justify against.
   The default answer is no; justification must advance at least one of
   the four claims without weakening any other.

5. **A new verb set contract or gate envelope version ships.** The gate
   envelope (`crates/zp-gate-envelope`) is currently at `ZP-Sig v1`. If a
   v2 ships with different signing semantics, the contract's Required agent-
   side affordance #3 should be updated to name which versions are
   conformant and what the migration path is.

6. **A new principle is added to Architecture Part V½.** Each new principle
   may reclassify Optional affordances as Forbidden or make Required
   affordances more specific.

---

## 9. Refs

- `docs/design/governed-agent-runtime.md` — the GAR architecture specification;
  the design-spec source from which this contract's affordance partition is
  derived. The GAR gives the architectural rationale and IronClaw-specific
  depth; this contract gives the tier-scoped partition.
- `docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md` — the hub contract;
  §4 Tier 6 entry ("Agent / tool integration tier"); §5 contract template;
  §6 integration patterns (sign-then-act, project-not-decide)
- `docs/EDGE-TIER-CONTRACT-2026-06.md` — the template exemplar; established
  the Required / Optional / Forbidden partition and the composition-with-
  principles structure this doc follows
- `docs/ARCHITECTURE-2026-04.md` §4b — the cockpit-OS framing; the structural
  basis for agents-as-tenants, not agents-as-authority
- `docs/ARCHITECTURE-2026-04.md` Part V½ — the eight design principles from
  which every per-tier contract derives its affordance categories
- `docs/TOOL-STATE-ENGINE.md` — receipt-derived tool state; the "state is
  never stored, only derived" principle that shapes Required tool affordance #5
- `docs/TOOL-PROXY-DESIGN.md` — port management and ZP-as-reverse-proxy;
  the governed channel model that the tool-side Required affordances extend
- `crates/zp-gate-envelope` — the ZP-Sig v1 implementation; the canonical
  form of Required agent-side affordance #3
- `crates/zp-verbs` — the verb set; the canonical enumeration of governed
  actions agents can request through the gate
- `docs/CONSOLE-CONFORMANCE-CONTRACT-2026-06.md` — the adjacent Console tier
  that hosts cockpit agents; Required agent-side affordance #6 (surface
  results through substrate-authorized channels) composes with Console's
  event-routing Required affordance #4
