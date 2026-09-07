# Tool Opacity and Capability Classes

**Date:** 2026-07-04
**Status:** Design document
**Companion to:** `docs/AGENT-TOOL-CONTRACT-2026-06.md` (tier 6 affordances)
**Scope:** Classification of tool effects by substrate visibility; capability-class delegation model for tenant agents

---

## 1. The problem

The substrate's governance boundary is at tool invocation: the gate
evaluates whether the requesting agent holds a capability grant for the
named tool, produces a receipt, and the tool executes. But tools differ
fundamentally in whether the substrate can verify what happened *after*
invocation. A `chain_query` call reads the audit chain — the substrate
can verify the read, hash the result, and produce a receipt whose
content matches what was returned. A `shell` call spawns a subprocess —
the substrate sees "shell was invoked with args X" but cannot verify
what the process did with the host after it started. The gate receipt
says the action was *authorized*; it does not say the action's
*consequences* are substrate-visible.

This gap matters because the chain's four claims (Architecture Part I
§2) depend on the chain being an accurate record of what happened. When
a tool's effects are fully visible to the substrate, the chain captures
both authorization and outcome. When a tool's effects escape substrate
visibility, the chain captures authorization but not outcome — a partial
record masquerading as a complete one.

The current `GrantedCapability::ToolCall { tools: Vec<String> }` model
delegates by tool name. This is precise but low-altitude: an operator
issuing a delegation must enumerate individual tool names rather than
expressing intent at the level of "this agent can read the chain" or
"this agent can manage tool lifecycle." As the tool vocabulary grows,
name-enumeration becomes a maintenance burden and obscures the
meaningful authority boundary.

---

## 2. Binary classification: transparent vs opaque

Tools divide into two categories based on a single question: **can the
substrate independently verify the tool's effects?**

### Transparent tools

A tool is transparent when every side effect it produces is either
internal to the substrate or mediated through a substrate-controlled
interface whose output the receipt layer can canonicalize.

Examples:

- `chain_query` — reads the audit chain; the substrate owns the data
- `governance_posture` — queries computed posture from chain-derived state
- `tool_lifecycle` (list, probe, launch, stop) — all operations go
  through ZP API endpoints that produce their own receipts
- `zp_system_state` — reads substrate configuration; no external side effects
- `chain_render` — reads and narrates chain data
- `memory_search`, `memory_read`, `memory_write` — workspace operations
  mediated through the substrate's persistence layer

For transparent tools, the receipt captures both "this was authorized"
and "this is what happened." The chain is a complete record.

### Opaque tools

A tool is opaque when its effects escape the substrate's verification
boundary — the tool produces consequences the substrate cannot
independently observe, hash, or attest to.

Examples:

- `shell` — spawns an arbitrary subprocess; the substrate sees the
  invocation args and captured stdout/stderr but cannot verify what the
  process did to the filesystem, network, or other host resources
- `file_write`, `apply_patch` — writes to the host filesystem; the
  substrate sees the declared path and content but the actual disk state
  is outside chain authority
- `http` / `web_fetch` — makes network requests; the substrate sees the
  declared URL and response but cannot verify what the remote endpoint
  did with the request or whether the response was faithfully reported
- Any tool that produces side effects on external systems (email sends,
  API mutations, webhook triggers)

For opaque tools, the receipt captures "this was authorized" and "this
is what the tool *reported* happened." The chain records the tool's
self-report, not independently verified truth.

### Why binary, not three-tier

An earlier analysis proposed a middle tier — "lifecycle" tools that
operate through substrate endpoints but produce host-level effects
(launching processes, stopping services). In practice, these are
transparent: every lifecycle operation goes through a ZP API endpoint
that produces its own receipt chain. The substrate sees the launch
request, issues a delegation, observes the health check, and records
the outcome. The effects are substrate-mediated even when they touch
the host.

The test is simple and doesn't admit a middle: either the substrate can
independently verify the effect, or it cannot. Lifecycle operations
pass that test. Shell invocations do not. No gradation is needed.

---

## 3. Capability classes

Instead of delegating individual tool names, the substrate groups tools
into capability classes that express meaningful authority boundaries.
Each class maps to a set of tools; delegating the class delegates all
tools in it. The operator thinks in terms of authority ("this agent can
read the chain"), not in terms of implementation ("this agent can call
`chain_query` with operation `entries`").

### Transparent classes

| Class | Authority granted | Tools |
|-------|-------------------|-------|
| `chain:read` | Read the audit chain — entries, receipts, head, integrity verification, statistics | `chain_query`, `chain_render` |
| `chain:write` | Write to the chain — emit receipts, create entries (currently substrate-internal; future agent-authored receipts) | (future) |
| `governance:read` | Query governance state — posture, delegation status, constitutional rules, system state | `governance_posture`, `zp_system_state` |
| `tool:lifecycle` | Manage the governed tool fleet — list, probe, launch, stop | `tool_lifecycle` |

### Opaque classes

| Class | Authority granted | Tools |
|-------|-------------------|-------|
| `host:execute` | Execute arbitrary commands on the host | `shell` |
| `host:write` | Write to the host filesystem | `file_write`, `apply_patch` |
| `network:egress` | Make outbound network requests | `http`, `web_fetch` |

### Class properties

Transparent classes are *substrate-verifiable*: the chain captures both
authorization and outcome. Delegating transparent classes grants the
agent broad substrate awareness without granting host-level authority.
An agent with `chain:read + governance:read + tool:lifecycle` can see
everything the substrate knows and manage the tool fleet, but cannot
touch the host filesystem or network.

Opaque classes are *self-reported*: the chain captures authorization
and the tool's account of the outcome. Delegating opaque classes grants
host-level authority whose consequences escape the chain's verification
boundary.

---

## 4. Proportional officer vigilance

The officer cadre's observation posture scales with opacity. This is
not punitive — opaque tools are legitimate and sometimes necessary.
It is proportional: actions whose effects the substrate cannot verify
independently receive more scrutiny from the officers who can observe
host state.

### Transparent tool invocations

Standard observation posture. Steward verifies chain integrity after
the receipt lands. Sentinel checks the delegation scope was not
exceeded. Forge notes the operational event. No elevated scrutiny —
the chain is a complete record.

### Opaque tool invocations

Elevated observation posture. Each officer runs specific verification
checks after the receipt for an opaque invocation lands on the chain.

**Forge: host-state verification.** Forge already has the sensor layer
(`zp-sensors`) — kqueue file watches, kqueue PID watches, port
discovery via `listeners`. After an opaque tool receipt lands, Forge
runs checks keyed to the tool class:

- `host:execute` (shell): Capture the process tree snapshot before and
  after invocation. Diff for new PIDs. For each new PID: resolve its
  binary path, check if it's still running at sweep time, check if it
  bound any ports (cross-reference against `listeners` scan). If a
  shell invocation's receipt says "exited 0, output: X" but Forge
  finds the command spawned a backgrounded child process still
  listening on port 9102 — that's a finding. Specific signals: new
  entries in the port scan that don't appear in the tool registry;
  new PIDs whose parent traces to the shell invocation's PID; child
  processes that outlive the shell invocation's reported exit.

- `host:write` (file_write, apply_patch): Stat the declared path. If
  the file exists, BLAKE3-hash the content and compare against the
  content hash in the receipt. If the hashes match, Forge attests
  agreement. If they diverge — file was modified after write, or the
  write reported success but the file doesn't exist — that's a
  finding. Specific signals: `stat()` returns ENOENT for a path the
  receipt claims was written; content hash mismatch; file permission
  bits that weren't in the receipt (e.g., the file is executable but
  the write didn't declare executable intent).

- `network:egress` (http, web_fetch): The substrate cannot verify what
  a remote endpoint did with the request. Forge's check is narrower:
  verify the response status code and content-length in the receipt
  are plausible (not fabricated by the tool). If the receipt claims a
  200 response from a host that Forge can re-probe and gets a DNS
  failure or connection refused — the endpoint is unreachable, so the
  receipt's claim is suspect. Specific signals: DNS resolution failure
  for the declared host; TCP connection refused on re-probe; response
  size in receipt exceeds what the endpoint serves on independent
  fetch. Note: re-probing has limits (endpoints may be stateful, rate-
  limited, or auth-gated), so Forge flags rather than concludes.

**Sentinel: scope and pattern analysis.** Sentinel evaluates whether
the opaque invocation's parameters are consistent with the agent's
active delegation scope and whether the invocation matches known
escalation patterns.

- Shell commands: Sentinel parses the command string (not executes it)
  for structural signals. Specific flags: `nohup`, `&` (backgrounding),
  `disown`, `setsid` (session leader — intent to outlive parent);
  `sudo`, `doas`, `chmod +s` (privilege escalation); `curl | sh`,
  `wget -O - | bash` (remote code execution); `rm -rf`, `mkfs`,
  `dd if=` (destructive operations); port-binding keywords (`listen`,
  `bind`, `serve`, `--port`). Each flag is a finding with a severity
  level, not a block. Sentinel does not parse shell semantics deeply —
  it pattern-matches on known-dangerous structural forms.

- File writes: Sentinel checks the target path against sensitive
  locations: `/etc/`, `~/.ssh/`, `~/.config/`, cron directories,
  systemd unit paths, shell profile files (`.bashrc`, `.zshrc`,
  `.profile`). Writes to these paths are findings regardless of
  content. Sentinel also flags writes that create executable files
  (`chmod +x` in a preceding or following shell invocation touching
  the same path).

- Network egress: Sentinel maintains a baseline of endpoints the agent
  has previously contacted (derived from prior receipts in the current
  session). A request to a novel domain is a finding; a request to a
  known domain is not. Sentinel also flags requests to RFC 1918
  addresses (internal network probing), metadata endpoints
  (169.254.169.254), and known exfiltration-associated ports (DNS over
  non-53, HTTPS over non-443 to novel hosts).

**Steward: receipt-reality coherence.** Steward's job is structural:
does the chain's account of what happened match observable reality?
Steward consumes Forge's verification results and Sentinel's pattern
findings, and synthesizes a coherence assessment.

- Count opaque receipts emitted in the current session. Count
  observable host-state changes Forge detected (new files, new
  processes, new ports). If host-state changes significantly exceed
  receipt count — e.g., the agent emitted 3 shell receipts but Forge
  found 7 new processes and 4 new files — the chain is under-recording
  relative to actual effects. That's a finding.

- If Forge reports a content-hash mismatch on a file write, or a
  shell-spawned process that outlived its receipt, Steward escalates:
  the chain says one thing, the host shows another. This is not a
  judgment call — it's a structural divergence between the chain's
  claims and observable fact.

- Steward does not assess *intent* (that's Sentinel's domain) or
  *host state* (that's Forge's domain). Steward assesses *whether the
  chain is a reliable record given what the other officers found*.

### Findings, not blocks

The officers do not block opaque tool calls — that is the gate's job,
and the gate already decided. Officers observe after the fact and emit
findings as receipts on the chain. Each finding has a severity
(informational, warning, alert) and a specific signal that triggered
it. The operator sees findings in their chain and can act on them:
revoke a delegation, narrow a capability class, or acknowledge the
finding as expected behavior. The officer cadre is the substrate's
immune system for the opacity gap — detection and surfacing, not
prevention.

---

## 5. The governance boundary gap

The current architecture has a structural gap: the governance boundary
is at tool *invocation*, not at resource *creation*. When an agent
calls `shell` and the subprocess spawns a long-lived process that
binds a port, opens network connections, or writes files — those
resources exist outside governance. The chain records "shell was
invoked"; it does not record "shell created a process that is now
listening on port 9102 and accepting HTTP connections from the
internet."

Shell is the primary governance escape hatch. An agent with `shell`
access can, in principle:

- Spawn ungoverned processes invisible to the chain
- Bind ports without going through the ZP port registry
- Make network requests without going through governed network policy
- Write files without going through governed filesystem mediation
- Install software without going through the tool lifecycle

The port-binding sensor layer (`zp scan`, the lsof test) catches some
of this after the fact — it detects processes holding ports that aren't
in the tool registry. But it misses ephemeral compute: a subprocess
that runs for 30 seconds, makes API calls, writes results to disk, and
exits leaves no port-binding trace for the sensor to find.

This gap is not a bug to fix in the current architecture — it is a
structural property of the opacity boundary. The fix is not to ban
opaque tools (they are necessary) but to make the gap visible and
bounded:

1. **Capability-class delegation makes the gap explicit.** An operator
   delegating `host:execute` knows they are granting authority whose
   consequences escape chain verification. The class name says what it
   means.

2. **Proportional officer vigilance makes the gap observable.** The
   officers cross-reference self-reported outcomes against host state,
   surfacing discrepancies as findings.

3. **The governed spawn primitive (future) closes the gap for
   cooperative tools.** An agent that needs a subprocess can use
   `spawn_governed_tool` instead of `shell` — the spawn operation
   registers the process with ZP, issues it a delegation, and brings
   it into the governance domain before it executes. The chain records
   not just "a process was requested" but "a process was launched,
   registered, delegated, and health-checked." This is the transparent
   alternative to the opaque `shell` path. Agents that use it get
   substrate-verified process lifecycle; agents that use raw `shell`
   get self-reported outcomes with elevated officer scrutiny.

---

## 6. Tenant delegation model

For any tenant framework, capability-class delegation
replaces tool-name enumeration. The operator delegates capability
classes to the tenant; the tenant projects those classes into its own
native tool surface.

### Current state

A tenant receives `GrantedCapability::ToolCall { tools: vec!["*"] }`
from `register_agent_handler` — a wildcard covering all tools. This
is operationally simple but semantically opaque: the wildcard says
nothing about what authority classes the operator intended to grant.

### Target state

The operator delegates named capability classes:

```
zp delegate grant {tenant} \
  --capabilities chain:read,governance:read,tool:lifecycle,host:execute,host:write,network:egress
```

The gate resolves each class to its constituent tools at evaluation
time. The chain records the class-level delegation, not the individual
tool names — so when a new tool is added to a class, existing
delegations cover it without re-issuance.

A tenant's internal tool registry projects the delegated classes into
its native tool surface: if `chain:read` is delegated, the
`chain_query` and `chain_render` tools appear in the tenant's tool
vocabulary. If `host:execute` is not delegated, `shell` does not
appear. The projection is deterministic from the chain — restart
the tenant and the same tools appear, because the chain hasn't changed.

### Class-to-tool resolution

The gate maintains a class registry mapping each capability class to
its constituent tool names. The registry is itself chain-anchored: the
operator can inspect which tools a class covers before delegating it.
Adding a tool to a class is an architectural act that produces a
receipt — the operator sees "tool X was added to class Y" on the
chain and can review whether the expanded class still matches their
intent.

---

## 7. Composition with principles

**P1 (signing is gravity).** The opacity classification exists because
P1 demands that receipts be structurally meaningful. A receipt for a
transparent tool is a complete attestation — the substrate verified the
effect. A receipt for an opaque tool is a partial attestation — the
substrate verified the authorization but not the effect. Making this
distinction explicit is what lets the substrate treat them differently
without pretending they are the same.

**P3 (there is no center).** Capability-class delegation prevents the
agent from becoming an authority center. The agent does not decide what
classes it holds — it reads the chain, discovers its grants, and
projects them into its tool surface. Class membership is chain-derived,
not agent-asserted.

**P4 (every bit counts).** Capability classes eliminate the redundant
data path of enumerating individual tool names in delegations. One
class name covers a meaningful authority boundary; individual tool names
are an implementation detail the operator should not need to track.

**P6 (a tool is intent, crystallized).** The class name carries the
semantics: `chain:read` means "read the audit chain," not "call
chain_query with operation entries or receipts or head." The class is
the crystallized intent; the tool names are the implementation.

---

## 8. Relationship to AGENT-TOOL-CONTRACT

This document extends the Agent/Tool Contract (§3, Required agent-side
affordance #2: "Request all capability invocations through the gate")
by classifying what the gate evaluates *against*. The contract says the
gate must mediate; this document says the gate mediates against
capability classes, not tool names, and that the gate's receipt has
different attestation weight depending on whether the tool is
transparent or opaque.

The contract's Forbidden agent-side affordance #2 ("Bypassing the gate
to invoke side effects directly") gains sharper teeth here: an agent
that bypasses the gate for an opaque tool has produced host-level
effects with neither authorization nor observation. The gap between
chain and reality is maximized.

The contract's Required tool-side affordance #3 ("Declare side effects
and required capabilities in machine-readable form") composes with
opacity classification: a tool's capability declaration should include
its opacity class, so the gate can route the invocation to the
appropriate officer vigilance posture without runtime classification.

---

## 9. Implementation notes

### Phase 1: Classification metadata

Add an `opacity: transparent | opaque` field to the tool registration
schema. Each tool declares its classification at registration time.
The gate reads the classification and annotates the receipt with it.
Officers key their vigilance posture on the receipt's opacity field.

### Phase 2: Capability-class delegation

Extend `GrantedCapability` with a `CapabilityClass` variant alongside
`ToolCall`. The gate resolves classes to tool sets at evaluation time.
The CLI's `parse_capabilities()` function gains class-name syntax.
Existing `ToolCall { tools: vec!["*"] }` wildcards continue to work —
they are a superset of all classes.

### Phase 3: Governed spawn

Implement `spawn_governed_tool` as the transparent alternative to
`shell` for long-lived process creation. The gate treats
`spawn_governed_tool` as a transparent lifecycle operation; `shell`
remains opaque. Agents that can use the governed path should; agents
that need raw shell access accept elevated officer scrutiny.

---

## 10. Autoregressive update triggers

1. **A new tool is added.** Classify it as transparent or opaque and
   assign it to a capability class. If no existing class fits, the tool
   either belongs to a new class (justify it) or is miscategorized.

2. **An opaque tool becomes substrate-mediated.** If a tool's effects
   move behind a substrate-controlled interface (e.g., `file_write`
   gains a governed filesystem layer), reclassify it as transparent.

3. **A new capability class is proposed.** The class must map to a
   coherent authority boundary — not a grab-bag of unrelated tools.
   If two proposed classes always co-delegate (operators never grant
   one without the other), they should be one class.

4. **Officer vigilance posture changes.** If Forge or Sentinel gain
   new host-observation capabilities, the gap between "self-reported"
   and "verified" narrows for some opaque tools. The classification
   doesn't change (the tool is still opaque) but the effective
   attestation strength improves.

5. **The governed spawn primitive ships.** Reclassify use cases that
   migrate from `shell` to `spawn_governed_tool`. The class boundary
   between `host:execute` (opaque) and `tool:lifecycle` (transparent)
   should absorb governed spawn naturally.

---

## 11. Refs

- `docs/AGENT-TOOL-CONTRACT-2026-06.md` — the tier 6 affordance
  partition this document extends
- `docs/ARCHITECTURE-2026-07.md` Part I §2 — the four claims
- `docs/ARCHITECTURE-2026-07.md` Part VII — the nine design principles
- `docs/GOVERNANCE-IMPLEMENTATION-PRINCIPLES-2026-06.md` — operational
  heuristics for building governance correctly
- `docs/design/TOOL-GOVERNANCE-LIFECYCLE-2026-07.md` — tool lifecycle
  receipts and state engine
- `crates/zp-core/src/capability_grant.rs` — `GrantedCapability` enum,
  `ToolCall` variant, `contains()` for delegation narrowing
- `crates/zp-server/src/lib.rs` — `lease_prereq_for_agent()`, gate
  evaluation, `register_agent_handler` wildcard grant
- A tenant's governance-tool file (e.g. `src/tools/builtin/zp_governance.rs`, external — a path in the tenant's tree, not this one) — the four governance
  tools this classification covers
