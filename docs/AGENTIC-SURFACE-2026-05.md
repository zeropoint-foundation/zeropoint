# The Agentic Surface

*Drafted 2026-05-09. Candidate for folding into `ARCHITECTURE-2026-05.md` as section II.14.*

## The reframe

"Where does the UI live" is a 2020 question. The 2026 answer is: **there is no
UI**, in the sense of "an HTML surface a human visits." The sovereign sits in
front of their assistant — Claude, ChatGPT, a CopilotKit app, whatever agentic
shell they prefer — and the substrate is something that assistant *consumes*,
not something the user navigates to.

This means three things for ZP:

1. **MCP is how assistants invoke substrate verbs.**
   The gRPC verb set (Architecture II.13) is exactly the right shape for a
   Model Context Protocol tool catalog. Every verb maps 1:1 to an MCP tool
   with no impedance mismatch.

2. **AG-UI is how assistants stream substrate state to humans.**
   Receipts are typed, signed, chained events. The subscriptions service in
   the verb set is already an event-stream contract. AG-UI is a serialization
   shim over that stream.

3. **A2A is how substrates negotiate with each other.**
   When a ZP node hands off a delegation to another node, or composes trust
   under V.5 (trust portability), that is agent-to-agent communication at the
   substrate layer. The libp2p mesh is the natural transport.

The substrate's job is to be a first-class participant in all three
protocols. It is not to ship its own HTML.

## What ZP already has that fits

Architecture II.13 (pure gRPC, HTTP/JSON deprecated entirely) is the right
outer surface for an MCP shim — gRPC verbs map 1:1 to MCP tools. The seven
services in `proto/v1/` collapse into a coherent agent tool catalog:

| Verb | Agent-facing intent |
|------|--------------------|
| `Guard.EvaluateGate` | "ask permission" |
| `Receipts` queries | "show me what happened" |
| `Delegation` verbs | "scope what I let agents do" |
| `Audit` query/watch | "trace this trajectory" |
| `Subscriptions` | "stream me updates as they happen" |
| `Mesh` queries | "show me peer state" |
| `NodeStatus` | "is this node healthy" |

`ActorRef.ACTOR_KIND_AGENT` is already first-class identity. The libp2p
adapter (Architecture II.10) gives the transport substrate-to-substrate
negotiation needs. The receipts model is already designed for citation:
`ReceiptRef` (reserved for V.7 receipt composability) is the seam.

The whitepaper-level thesis was always that ZP is agent-native trust
infrastructure. The verb-set arc just made the contract explicit. This
section makes the agentic-protocol surface explicit too.

## The four adapter crates

Per Architecture II.0 (contracts singular, implementations plural), each
agentic protocol becomes a documented adapter. The contract is the gRPC verb
set; the adapters translate. Adapters never reach into `zp-server` or
`zp-audit` directly — they import from `zp-verbs` and translate.

| Crate | Role | Status |
|-------|------|--------|
| `zp-mcp` | Exposes gRPC verbs as MCP tools. Any MCP-aware assistant can drive ZP. | Missing — supersedes the removed `zp-agent-bridge` |
| `zp-agui` | Wraps the `Subscriptions` service in AG-UI event format. Any AG-UI client can render substrate state. | Missing |
| `zp-a2a` | Substrate-to-substrate negotiation, layered over libp2p. Couples to V.5 trust portability. | Missing — exploratory until V.5 opens |
| `zp-mesh` (libp2p adapter) | Transport for A2A and substrate gossip. | Present |

A new discipline pin keeps the surface coherent:
**`every_verb_has_mcp_mapping`** — every public verb in `proto/v1/` must have
a corresponding MCP tool definition in `zp-mcp`. Analogous to
`verbs_must_match_schema`, but for the agentic surface.

## The compensating-receipt gap

The current verb set has no concept of *compensating receipt* or *rollback
intent*. Agentic UX strongly wants this — when an agent asks the user "I did
X, want me to undo it?" the substrate needs primitives for that. Without
them, every assistant has to reinvent the rollback story.

Phase 3 verb-set work should add:

- `RECEIPT_KIND_COMPENSATION` to the receipt kind enum
- A `Compensate` verb on the `Receipts` service
- Schema: a compensation receipt cites the original via `ReceiptRef` with
  relation `"compensates"`

This is not a substitute for verifiability. The original receipt remains in
the chain. The compensation appends. The chain stays append-only; what
shifts is the operational state derived from the chain. Verifiers can
distinguish "this happened and was compensated" from "this didn't happen."

## The protocol-pinning tension

MCP, AG-UI, and A2A are all protocols controlled by other organizations
(Anthropic, LangChain ecosystem, Google). Building ZP's surface around them
ties ZP's evolution to theirs.

The mitigation is structural: **the gRPC verb set stays the contract; the
protocol adapters are swappable.** If AG-UI v2 changes shape, or A2A
fragments, or some new agentic UI protocol wins, the adapter swaps — the
substrate doesn't move. This is exactly what Architecture II.0 was designed
to enable.

The discipline pin enforces this: adapters live in `zp-{protocol}` crates,
they import from `zp-verbs` and translate, and they never reach into
`zp-server` or `zp-audit` directly. A future audit-doc check should verify
adapter crates have no direct dependency on substrate-internal crates.

## Implications

**The UI surface decision is resolved.** All four UI pages
(dashboard/onboard/speak/ecosystem) die. The four `*_HTML` constants and
their asset files become deletable in their entirety, not merely orphaned.

- **Onboard** moves to MCP-driven local invocation. The assistant calls
  `zp.onboard.start`; the local zp-server runs the Genesis ceremony; the
  Touch ID / sovereignty prompt happens at the OS layer; AG-UI events stream
  the ceremony state back to the assistant for human-readable narration. The
  Genesis key still never leaves the local machine.
- **Dashboard** moves to AG-UI subscriptions any assistant can render. The
  user asks "what's my audit chain look like?" and the assistant answers from
  live substrate state.
- **Speak** deprecates into the `zp speak` CLI (already exists).
- **Ecosystem** moves to `zeropoint.global` as marketing, where it belonged.

**The SDK narrative shifts.** Course content changes from "here's how to call
ZP HTTP routes" to "here's how to plug ZP into your agentic stack via
MCP/AG-UI/A2A." The course-track update task becomes a substantive rewrite,
not a refresh.

**Phase 2a's dead-code sweep proceeds without architectural ambiguity.** The
HTML constants aren't pending a UI restoration; they're fully deletable.

## Sequencing

In dependency order:

1. **Phase 2a follow-up — dead-code sweep.** Removes the 28 dead-code
   warnings. Clean slate.
2. **Phase 2b — substrate routes to gRPC handlers.** Prerequisite for
   adapters; the gRPC server has to be running before MCP can wrap it.
3. **`zp-mcp` adapter.** First agentic surface. Exposes verbs as tools.
4. **`zp-agui` emitter.** Second agentic surface. Wraps subscriptions.
5. **Discipline pin `every_verb_has_mcp_mapping`.** Lands alongside (3) once
   `zp-mcp` is reviewable.
6. **Compensating receipts (verb-set Phase 3).** Fills the rollback gap.
7. **`zp-a2a` adapter.** When V.5 trust portability opens.

The course content update lands alongside (3-4) as the agentic surface
becomes demonstrable.

## Open questions

- **Should `zp-mcp` ship as a sidecar binary, an in-process module of
  zp-server, or both?** Sidecar gives clean process isolation; in-process
  gives lower latency. Probably both, with the in-process path as default.
- **What is the agent identity story when an assistant invokes a verb on
  behalf of a user?** The receipt's `ActorRef.target` is the user; the
  `ActorRef.issuer` is the agent's signing key. Need a clean delegation
  path so agent-issued receipts cite their authorizing delegation. This
  ripples back to delegation narrowing design.
- **AG-UI subscriptions vs. polling.** AG-UI is push-oriented; the
  subscriptions service streams. But agents that prefer polling should be
  able to. Subscriptions probably needs a "snapshot" verb companion.
- **Compensation semantics.** Are compensating receipts always issued by
  the original actor, or can a sovereignty holder issue them on behalf of
  an agent? Probably the latter, with an authorization receipt cited.
