# REGENT MODES — Canonical Configuration Shifting

**Draft for discussion** · 2026-08-13 · Prompted by Agent Zero v2.9 (Agent Editor)

> **Thesis:** Agent Zero solved profile management. It did not solve profile *authority*. ZeroPoint should not copy the profile; it should canonicalize the mode. A Regent mode is a signed attenuation of the Regent's standing grant, not a config file that layers over defaults.

---

## 1. What Agent Zero v2.9 actually shipped

Stripped of UI, the Agent Editor is four things:

| Feature | Mechanism |
|---|---|
| Profile creation | Sparse, non-destructive overrides layered on defaults + inherited profiles |
| Identity / instructions / model preset | Per-profile prompt and model binding |
| Tool · MCP · Skill policy | Default switch + per-item allow/deny, enforced at prompts, schemas, execution, and delegated agents |
| Scoping | Global or project-scoped profiles with inheritance |
| `/profile "name" "description"` | One command creates the profile and a fresh chat bound to it |

The enforcement claim is the interesting part — *"enforced everywhere: prompts, schemas, execution, and delegated agents."* That is a genuinely four-surface enforcement story, and more than most frameworks attempt.

But it is enforcement by configuration. The policy is trusted because it is present in the profile. This is precisely the sixth governance gap in GAR §2: *"A tool is trusted because it is present, not because it was recognized."* A0 can tell you what a profile says now. It cannot tell you what the profile said when the agent took the action, who authorized the change, or whether the file was edited between the grant and the act.

That gap is the whole opportunity.

---

## 2. What ZeroPoint already has that A0 does not

The Regent's tool surface today is `REGENT_TOOLS` in `zp-regent/src/tools.rs` — a compile-time `const` of 15 `RegentTool { name, scope }` pairs, consumed by `zp-server` to build the startup `CapabilityGrant`. One declaration, deliberately, after the 2026-08-09 consolidation.

So the substrate is already right in the way that matters:

- **Every tool already carries a capability scope**, not just a name. `browser_use` → `web:allowed_domains`. A0's per-item toggle is a boolean; ZeroPoint's is a scope selector.
- **The grant is already a chain object.** Modes do not need a new authority mechanism; they need to *narrow* an existing one.
- **Delegation depth and TTL already exist.** A0's "enforced on delegated agents" falls out of capability delegation rather than needing separate plumbing.
- **Persona is already separated from capability.** `persona.rs` is explicit: *"The persona does not control what the Regent does (that's the cognitive loop). It controls how the Regent communicates."* A0 fuses identity, instructions, model, and policy into one profile object. Keeping them on separate axes is the better decomposition and you already have it.

---

## 3. Proposed model: mode as canonicalized attenuation

**A mode is a signed receipt that narrows the standing grant. It can only subtract.**

```rust
/// A named, canonicalized narrowing of the Regent's standing capability.
/// Modes are monotone: a mode may only remove from REGENT_TOOLS, never add.
/// Escalation requires a new grant — an authority decision, per PIN-001.
pub struct RegentMode {
    /// Stable slug. Canonicalized; the anchor is chain-resident, not file-resident.
    pub slug: &'static str,

    /// Subset of REGENT_TOOLS by name. Validated at construction against the
    /// single declaration — a mode naming a tool that is not granted fails to
    /// canonicalize rather than silently granting it.
    pub tools: &'static [&'static str],

    /// Per-tool scope narrowing. `browser_use` may be granted in research mode
    /// under `web:allowed_domains=[arxiv.org]` while the standing grant is wider.
    pub scope_overrides: &'static [(&'static str, &'static str)],

    /// Context files loaded for this mode (the "soul file" problem, solved with
    /// provenance metadata rather than bare concatenation).
    pub context: &'static [ContextBinding],

    /// Routing overrides layered on officer-inference.toml.
    pub routing: Option<RoutingProfile>,

    /// Persona binding. Orthogonal to capability — a mode selects a voice,
    /// it does not define one.
    pub persona: PersonaRef,
}
```

The four properties this buys that a profile file cannot:

1. **Attenuation-only is structurally safe.** No mode can escalate. The dangerous direction is closed by construction, so mode authoring does not need to be an authority-grade operation — only mode *definition against the standing grant* does, and that validates automatically.

2. **Mode shifts are receipts.** `rcpt-mode-shift{from, to, reason, operator_sig}` chains between the mode's activation and every action taken under it. "Which configuration was the Regent in when it did X" becomes a chain query, not an archaeology exercise. A0 structurally cannot answer this.

3. **The mode registry lives in the chain, not on disk.** A profile file can be edited between authorization and act. A canonicalized mode cannot — editing it produces a new canon and a visible chain divergence. This is the Year Zero argument applied to configuration.

4. **Delegated sub-agents inherit an attenuated grant, automatically.** A mode-scoped delegation is just a `CapabilityGrant` with `max_delegation_depth` and the mode's tool subset. No separate enforcement path, so no separate place to drift.

---

## 4. The failure mode to design against

This is the concrete risk, and it is already visible in the code.

`sanitize_tool_name` matches emitted tool names with `starts_with` across the full `REGENT_TOOLS` list, and the test `tool_names_are_prefix_free` holds that matching order-independent. If a mode narrows the *active* set but the sanitizer keeps matching against the *full* set, then a tool that is granted-but-out-of-mode sanitizes cleanly and dispatches — and the gate is the only thing standing between that and execution.

Worse, the diagnostic collapses: an out-of-mode call and an unknown-tool call would produce the same "unknown tool" signal, which is exactly the two-day-drift failure the `tools.rs` docstring narrates ("`report_assemble` arrived, failed to sanitize, and dispatched as unknown tool while the tool existed and was reachable").

**So:** sanitization must resolve against the active mode's set, and out-of-mode must be its own outcome — `Intent::Execute` rejected with `OutOfMode { tool, active_mode }`, receipted, and surfaced to the model as a *reason* it can plan around. Not an error it reads as a formatting mistake and retries.

Second risk, milder: mode explosion. Fifteen tools yield a lot of possible subsets, and the corpus discipline problem you already have with 45 crates and a 109KB CLAUDE.md will reassert itself. Ship three or four modes with real distinct purposes, derived from the one declaration. Do not build a mode editor before there are modes worth editing.

---

## 5. Where pi fits — coding mode is the proof case

This is why the two threads converge.

The Regent does not need to become a coding agent. It needs a **coding mode** whose tool subset includes a bridge to an external harness, and pi is the right first harness for that because it exposes an RPC protocol and SDK — it can be *driven* as a subordinate process, which Claude Code cannot.

```
Regent (coding mode)
  └── grant: attenuated, scope `harness:pi:workspace=<path>`
      └── drives pi over RPC
          └── @zeropoint/trace-pi extension
              ├── tool_call  → zp.gate_tool_call → allow/deny
              └── tool_result → receipt → chain
```

Every action pi takes chains back under the Regent's mode receipt. The Regent delegated, the harness executed, the chain records both, and the delegation expires when the mode shifts. That is the portable-trust claim demonstrated end to end on a real workload — and it is the same shape you would reuse for a research mode driving a browser, or an ops mode driving Sentinel.

It also closes the README gap: pi stops being the first box in a diagram with no code behind it.

---

## 6. Suggested sequence

1. **`@zeropoint/trace-pi`, trace layer only.** No mode work. Proves `@zeropoint/trace` can exist as a package and gives the receipt schema its first non-Rust producer. Smallest possible thing that makes the README true.
2. **Guard layer on the same extension.** Requires the `/api/v1/gate/tool_call` endpoint, which the GAR spec already specifies as `zp.gate_tool_call`. Fail-closed default.
3. **`RegentMode` as attenuation, three modes hardcoded** — `steward` (default, current surface), `coding`, `research`. No editor. Validate against `REGENT_TOOLS` at construction; fix the sanitizer to resolve against the active set.
4. **`rcpt-mode-shift` + chain query.** The demo is: *show me every action the Regent took in coding mode last week, and prove the mode was authorized before the first one.*
5. **Editor UI in the cockpit — last.** By then the component catalog work in GAR §3.2 has a real thing to render, and mode authoring is a policy proposal that goes through Guard → Policy → Audit like everything else.

The ordering matters: A0 built the editor because profiles already existed and were painful to edit by hand. Building the editor first, before modes are load-bearing, would be building their solution to a problem you do not have yet.
