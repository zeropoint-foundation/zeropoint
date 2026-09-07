# Chain Storytelling Architecture & Cleo Officer

**Document type:** Tier 2 canonical elaboration. Elaborates KEEL §II.6 (officer signing keys) and §III.4 (officer charters) — Cleo's charter and the chain-narration primitives. Reclassified Tier 2 on 2026-07-10.

*2026-06-30. Chain narration as a substrate primitive, not a cockpit feature.*

## Motivation

The chain is the single source of truth — but it's operationally mute. `zp audit log` dumps raw entries: timestamp, hash, action debug repr. `zp audit verify` confirms hash linkage. Neither tells a story. To understand "what happened," an operator either reads raw JSON or asks the Regent (cockpit-dependent, LLM-interpreted, ephemeral).

That gap means chain legibility requires a cockpit. A ZP deployment without any cockpit/the Regent can write to the chain and verify its integrity but cannot read its own history in human terms. This violates Principle 3 (there is no center) — the chain's legibility depends on an external agent.

Chain storytelling must be a substrate primitive: deterministic, template-driven, available via `zp` CLI, no LLM required.

## Two questions, two officers

The existing officer cadre asked one class of question: **is the system healthy?** (Steward). The chain storytelling work reveals a second class: **what happened, and was it legitimate?**

These are structurally different inquiries with different sweep patterns, different finding types, and different output modes. Steward checks structural invariants (hash integrity, signature coverage, growth anomalies, vault hygiene). The governance narrative — who held authority, how it flowed, whether rules were followed — is a distinct domain that Steward shouldn't own.

### Officer: Cleo (`cleo`)

**Domain:** `governance`

**Charter:** Read the receipt chain and tell the coherent story of how authority, trust, and delegation moved through the system. Explain not just *what* happened, but *why* that authority was granted or revoked, and *where* governance rules were followed or violated. Extended (July 2026) to include proposing delegation-lifecycle actions during tool intake and other governance-lifecycle events — Cleo emits structured proposals (initial delegation scopes for newly-discovered tools, renewals for delegations approaching expiry, revocations for orphaned or scope-exceeded grants) that the operator signs. Proposals are governance narrative made actionable: Cleo already reads the governance story; proposing next steps is the natural extension. This resolves the role-scope conflict identified in the July 2026 corpus audit between narrator-only and delegation-lifecycle-proposer framings.

**Key distinction:**
- Steward tells you whether the system is **healthy and consistent**.
- Cleo tells you the story of **who had power, how they got it, and whether they abused it or followed the rules** — and proposes the next governance-lifecycle actions the operator should sign.

**Sweep checks:**

| Check | Finding type | What it detects |
|-------|-------------|-----------------|
| Delegation lifecycle | `delegation_granted` | New delegation appeared on chain |
| Delegation lifecycle | `delegation_revoked` | Delegation withdrawn |
| Delegation lifecycle | `delegation_expired` | Delegation past TTL with no renewal |
| Delegation lifecycle | `delegation_renewed` | Delegation renewed (carries `renews: <prior>`) |
| Gate decisions | `gate_allowed` | Gate permitted an action, citing a delegation |
| Gate decisions | `gate_denied` | Gate blocked an action — missing or expired delegation |
| Gate decisions | `gate_denied_no_delegation` | Gate denied: no delegation exists for this subject |
| Authority chain | `authority_gap` | Action executed without a traceable delegation chain back to Genesis |
| Authority chain | `authority_chain_valid` | Full delegation chain verified from action to Genesis |
| Policy compliance | `policy_violation` | Action proceeded despite gate denial (should be structurally impossible; Critical if found) |
| Policy compliance | `unsigned_governance_action` | Governance-significant action (delegation, gate override) lacks a signature |
| Scope analysis | `delegation_scope_exceeded` | Delegated capabilities used beyond granted scope |
| Scope analysis | `delegation_narrowing_valid` | Sub-delegation correctly narrows parent scope |

**Watch patterns** (for real-time activation, Tier 2):
- `delegation:granted:*`
- `delegation:revoked:*`
- `gate:allowed:*`
- `gate:denied:*`

**Posture contribution:** Cleo's findings contribute to a **governance** posture domain. This is a fourth domain alongside integrity (Steward), security (Sentinel), and operations (Forge). See §Posture Model below.

## Steward scope reduction

With Cleo handling governance narrative, Steward's scope narrows to its core: structural integrity. Current Steward checks and their disposition:

| Current check | Stays with Steward | Reason |
|--------------|-------------------|--------|
| `check_chain_integrity` (hash linkage, signatures) | Yes | Structural integrity — Steward's core |
| `check_chain_growth` (silence, burst detection) | Yes | Growth anomalies are structural health |
| `check_vault_keys` (naming hygiene, orphans) | Yes | Vault structure, not governance |
| `unsigned_entry_ratio` | Yes | Signature coverage is integrity |

Nothing moves from Steward to Cleo in this phase. The checks Cleo adds are *new* — they read chain events that Steward currently ignores (delegation lifecycle, gate decisions, authority chains). This is additive, not a migration.

Future consideration: if Steward's `unsigned_entry_ratio` and Cleo's `unsigned_governance_action` overlap on the same entries, clarify precedence. Steward reports the aggregate ratio; Cleo reports specific governance entries that lack signatures. Both are valid, non-conflicting findings.

## Chain Story Primitives

### StorySegment

The atomic unit of narration. One segment grounds one or more chain entries into a human-readable sentence with structural classification.

```rust
/// A single narrated element of a chain story.
pub struct StorySegment {
    /// Chain entries this segment narrates.
    entry_ids: Vec<AuditId>,
    /// Human-readable narrative sentence.
    text: String,
    /// Structural classification for rendering and filtering.
    kind: SegmentKind,
    /// Time span covered by the referenced entries.
    span: (DateTime<Utc>, DateTime<Utc>),
    /// Which officer produced this segment (if from a sweep).
    /// None for segments generated by the narration engine directly.
    source_officer: Option<&'static str>,
}
```

### SegmentKind

```rust
enum SegmentKind {
    // Governance (Cleo's domain)
    DelegationGranted,
    DelegationRevoked,
    DelegationExpired,
    DelegationRenewed,
    GateAllowed,
    GateDenied,
    AuthorityChainTrace,
    PolicyViolation,

    // Integrity (Steward's domain)
    IntegrityVerified,
    ChainSilence,
    ChainBurst,
    SignatureCoverage,

    // System events
    SystemStartup,
    SystemShutdown,
    OfficerHeartbeat,
    PostureChange,

    // Tool lifecycle
    ToolInvoked,
    ToolCompleted,
    ToolFailed,

    // Cognition (Regent / tenant agent interactions)
    MessageReceived,
    ResponseGenerated,
    ApiProxied,
}
```

### ChainStory

A sequence of `StorySegment`s constituting a complete narration over a time range or entry range.

```rust
pub struct ChainStory {
    /// Ordered segments (chronological).
    segments: Vec<StorySegment>,
    /// Chain entries covered.
    entry_range: (AuditId, AuditId),
    /// Time range covered.
    time_range: (DateTime<Utc>, DateTime<Utc>),
    /// Total chain entries in range.
    entry_count: usize,
}

impl ChainStory {
    /// Generate a deterministic story from chain entries.
    ///
    /// Each AuditAction variant maps to a template. No LLM.
    /// Officers contribute structured findings that become segments.
    pub fn from_entries(entries: &[AuditEntry]) -> Self { ... }

    /// Compressed summary: group related segments into arcs.
    /// "The Regent was delegated chain_render access and used it 3 times."
    pub fn summarize(&self) -> Vec<StorySegment> { ... }

    /// Filter to a specific domain or SegmentKind.
    pub fn filter(&self, kinds: &[SegmentKind]) -> ChainStory { ... }

    /// Render as plain text for CLI output.
    pub fn render_text(&self) -> String { ... }
}
```

### Narration templates

Templates are deterministic format strings, not LLM prompts. Examples:

| Chain event | Template |
|------------|----------|
| `delegation:granted:{subject}` | "Delegation granted to **{subject}** for **{capabilities}**, valid until {expiry}." |
| `delegation:revoked:{subject}` | "Delegation to **{subject}** revoked by **{actor}**." |
| `gate:allowed:chain_render` | "Gate allowed **{tool}** for **{actor}**, citing delegation **{grant_id}**." |
| `gate:denied:chain_render` | "Gate denied **{tool}** for **{actor}**: {reason}." |
| `officer:std:heartbeat` | "Steward swept at {time}: {finding_count} findings, max severity {severity}." |
| `posture:computed` | "System posture: {composite} ({trend}). Integrity {integrity}, security {security}, operations {operations}, governance {governance}." |

The narration engine (`ChainStory::from_entries`) matches `AuditAction` variants → templates, extracts fields from `PolicyDecision` conditions and `SystemEvent` event strings, and produces `StorySegment`s. Deterministic: same chain → same story, always.

## Crate location

The narration primitives (`StorySegment`, `SegmentKind`, `ChainStory`) live in `zp-officers` alongside the officer trait and finding types. Rationale: officers are the primary producers of narration context, and the narration engine reads chain entries through the same `ChainReader` handle officers use. No new crate needed.

Cleo's implementation (`cleo.rs`) follows the same pattern as `steward.rs`: implements `Officer`, returns `Vec<Finding>` from sweep, plus a new method for generating `Vec<StorySegment>` from chain entries. The `StorySegment` generation is a separate method — not part of the `Officer` trait — because not all officers narrate. Steward observes and reports; Cleo observes, reports, *and* narrates.

### Officer trait extension

The `Officer` trait stays unchanged. Narration is a separate concern:

```rust
/// Officers that can narrate chain state.
///
/// Not all officers narrate. Steward reports structural health
/// via findings. Cleo reports governance findings AND produces
/// human-readable narration of authority flow.
pub trait ChainNarrator: Officer {
    /// Generate story segments from chain entries.
    ///
    /// Deterministic, template-driven. No LLM.
    fn narrate(&self, chain: &ChainReader<'_>) -> Vec<StorySegment>;
}
```

Cleo implements both `Officer` (for sweep findings) and `ChainNarrator` (for story generation). The sweep runner calls `sweep()` for findings and `narrate()` for story generation. The CLI calls `narrate()` directly.

## Posture model evolution

Current: three domains (integrity, security, operations), composite = minimum.

With Cleo: **four domains** (integrity, security, operations, governance).

```rust
pub struct PostureScore {
    pub integrity: f64,    // Steward
    pub security: f64,     // Sentinel (future)
    pub operations: f64,   // Forge (future)
    pub governance: f64,   // Cleo
    pub composite: f64,    // min(all four)
    pub trend: PostureTrend,
}
```

Cleo's governance findings use the same severity → penalty mapping as other domains:
- Critical (-0.4): policy violation, authority gap
- Error (-0.2): unsigned governance action, scope exceeded
- Warning (-0.05): delegation expired without renewal
- Info/Ok (0.0): delegation granted, gate allowed, authority chain valid

A clean governance domain scores 1.0 — no governance anomalies detected. The composite posture now reflects all four domains, and the weakest still sets the ceiling.

## CLI surface

### `zp chain story`

Substrate-level chain narration. Deterministic, no LLM.

```
zp chain story                     # Full story, last 50 entries
zp chain story --limit 100         # Last 100 entries
zp chain story --since 2026-06-30  # Since date
zp chain story --summary           # Compressed arcs
zp chain story --domain governance # Filter to governance events
zp chain story --domain integrity  # Filter to integrity events
```

Example output:

```
  Chain Story — 286 entries, 2026-06-30 08:14 → 14:32

  08:14  System started (build e633f35, port 17010).
  08:14  Steward swept: 4 findings, max severity Warning.
         Chain integrity verified: 286 entries, 286 hashes valid.
         Chain silence: no entries in the last 47 minutes.
         Unsigned entry ratio: 280 of 286 (97%) lack signatures.
  08:14  System posture: 0.90 (Stable). Integrity 0.90, governance 1.00.
  08:15  Delegation granted to {tenant} for chain_render, valid 24h.
  08:15  Gate allowed chain_render for {tenant}, citing delegation #abc123.
  08:16  Gate denied tool_exec for unknown_agent: no delegation exists.
  08:17  Cleo swept: 3 findings, max severity Info.
         Delegation lifecycle: 1 active grant ({tenant}), 0 expired, 0 revoked.
         Gate decisions: 1 allowed, 1 denied. Denial was correct (no delegation).
         Authority chain valid: all allowed actions trace to Genesis.
```

### `zp audit log` — unchanged

Raw dump stays as-is. Forensic tool, not narrative tool.

## Two consumption tiers

### Substrate tier (no cockpit required)

`zp chain story` outputs deterministic text. Same input → same output, always. Available on any ZP deployment. Officers contribute findings and narration. The CLI renders `ChainStory::render_text()`.

### Cockpit tier (the Regent, future agents)

Cockpits read `StorySegment`s via a new API endpoint:

```
GET /api/v1/audit/story?limit=50&domain=governance
```

Returns `ChainStory` as JSON. the Regent adds interpretation:
- "The gate denied chain_render because the tenant's delegation had expired. Ken re-granted it, and the next attempt succeeded — three receipts documenting failure, intervention, and recovery."
- Wraps in visualization components from `<zp-receipt-chain>`.
- Ephemeral by default. Operator can sign to promote to artifact.

## Config

```toml
[officers]
enabled = true
sweep_interval_secs = 60
steward_enabled = true
cleo_enabled = true
```

Wiring follows the Steward pattern: `OfficersConfig` gains `cleo_enabled`, `spawn_sweep_task` adds `Cleo::new()` to the roster when enabled, config resolution in `zp-config` adds the field.

## Implementation plan

1. Add `StorySegment`, `SegmentKind`, `ChainStory`, `ChainNarrator` trait to `zp-officers`.
2. Implement `cleo.rs`: `Officer` + `ChainNarrator`. Sweep checks for delegation lifecycle, gate decisions, authority chain, policy compliance.
3. Add `governance` domain to `PostureScore`.
4. Wire Cleo into `crates/zp-server/src/officers.rs` (same pattern as Steward).
5. Add `cleo_enabled` to config schema and resolution.
6. Add `zp chain story` CLI subcommand.
7. Add `/api/v1/audit/story` endpoint for cockpit consumption.
8. Build, verify Cleo heartbeat receipts on live chain, verify `zp chain story` output.

## Design principles engaged

- **Signing is gravity** — Cleo reads signed entries; unsigned governance actions are findings.
- **There is no center** — chain storytelling is substrate-native, not cockpit-dependent.
- **Every bit counts** — deterministic templates, no LLM re-runs, no duplicate narration.
- **A tool is intent, crystallized** — `zp chain story` is the verb; the ChainNarrator trait is the contract.
- **Store-and-forward is primary** — the chain is the narrator's only input; story segments are derived, never stored.
- **The chain configures the cockpit** — cockpits read story segments as projections of chain state, not as independent configuration.
