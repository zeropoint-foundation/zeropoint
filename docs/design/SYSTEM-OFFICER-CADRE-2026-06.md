# System Officer Cadre — Design Document

**Document type:** Design specification  
**Author:** Ken Romero, with synthesis assistance from Claude  
**Date:** 2026-06-29  
**Status:** Draft  
**Companion documents:**
- `docs/ARCHITECTURE-2026-04.md` — Canonical Architecture Record (north star)
- `docs/VAULT-INTEGRITY-SYSTEM-2026-06.md` — Vault validation infrastructure (Steward's primary instrument)
- `docs/ARCHITECTURE-2026-04.md` Part VIII — Compute Surface Awareness (Forge's domain)

---

## 1. What This Is

Three dormant agents — **Steward**, **Sentinel**, **Forge** — inside `zp-server` that activate on chain events or periodic sweeps to check system health. They're not services; they're functions that run when conditions warrant.

Each has a clear domain. Each can read the others' findings via the chain. Final decision authority belongs to the domain owner. The operator retains veto via signing authority.

### 1.1 Why now

Three recent incidents: the vault integrity system proved ZP can self-validate and emit structured findings; 24,693 chain entries accumulated without automated hygiene; the gate agent-name→key mismatch persisted silently until a manual debug session caught it. Each should be caught automatically.

---

## 2. The Four Officers

### 2.0 Shared invariant: read-only observers

All officers are **read-only**. They read chain, vault, port registry, and process state. Their only write path is appending finding receipts to the chain. The `Officer` trait enforces this: read handles to substrate state, one `emit_finding()` method, no mutable references. If an officer needs something changed, it proposes. The operator signs. See R1 in §6 for the residual privilege risk.

### 2.1 Steward (Std) — Integrity

**Domain:** Chain integrity, vault coherence, configuration hygiene.

**Watches:**
- Chain continuity: hash linkage, signature verification, gap detection
- Chain growth rate: anomalous bursts or suspicious silence
- Vault hygiene: orphaned namespaces, malformed keys, leaked secrets in key names, empty entries
- Vault schema compliance: entries violating their tool manifest's `VaultVarSchema`
- Configuration drift: `config.toml` values contradicting vault state or chain receipts
- Receipt semantics: malformed receipts, missing required fields, schema mismatches

**Boundary:** Reports structural facts. Doesn't make security judgments (Sentinel's domain) or operational judgments (Forge's domain).

### 2.2 Sentinel (Sen) — Security

**Domain:** Credential lifecycle, authentication integrity, access anomalies.

**Watches:**
- Credential freshness: keys approaching rotation thresholds, expired tokens
- Authentication anomalies: gate denial patterns (`no_valid_delegation` clusters, `capability_scope_exceeded` repeats)
- Delegation health: grants approaching expiry, orphaned delegations, scope creep
- Secret hygiene: plaintext secrets in logs, env vars, or chain receipts
- Key material integrity: Genesis key accessibility, signing key consistency
- Identity coherence: agent registrations that don't match delegation grants (the `"ironclaw"` vs hex-key mismatch we fixed this session)

**Boundary:** Proposes rotation and revocation. Never executes either.

### 2.3 Forge — Operations

**Domain:** Process lifecycle, resource health, operational coherence.

**Watches:**
- Process inventory: running tools vs registered tools, orphans, zombies
- Port registry coherence: allocated vs actually-listening ports, stale bindings
- Resource health: disk space for chain/vault/logs, memory pressure
- Launch integrity: tools that fail to start, start but don't register, or register but become unresponsive
- Operational patterns: restart frequency (crash loops), health check flip-flops

**Boundary:** Surfaces findings and proposes actions. Never kills processes or allocates ports directly.

---

## 3. Shared Architecture

### 3.1 Runtime home — ZP-native, cockpit-agnostic

Officers are dormant subsystems inside `zp-server`. No separate processes, ports, or network surfaces. They share the server's access to chain, vault, port registry, and identity.

**ZP-native** because officers need direct trusted access to the chain and vault. Running them through IronClaw would make them subjects of the governance they're supposed to tend.

**Cockpit-agnostic** because officers never address a cockpit by name. They emit findings to the chain; cockpit agents (Sage, CLI, anything else) discover findings through the event stream (§3.5). Works identically regardless of which cockpit is running or whether any is.

### 3.2 Activation — dual mode

**Real-time chain watch (critical patterns):**
An internal subscriber receives every new chain entry as it's appended. The subscriber evaluates the entry against each officer's trigger patterns. If a pattern matches, the officer activates immediately.

Critical triggers (immediate activation):
- `gate:denied:*` with reason `no_valid_delegation` — Sentinel (identity coherence failure)
- `gate:denied:*` clustered (3+ in 60s) — Sentinel (access anomaly)
- Chain hash discontinuity — Steward (integrity violation)
- `tool:health:down:*` — Forge (process death)
- `delegation:revoked:*` — Sentinel (authority change)

**Periodic sweep (`system:sweep`):**
A timer fires every N minutes (configurable, default 15). Each officer runs its full diagnostic suite against current state. The sweep catches absence-of-events — things that *should* have happened but didn't:
- No health check from a registered tool in the last 2× its expected interval (Forge)
- No chain entries at all in the last hour when tools are supposedly running (Steward)
- Delegation grants approaching expiry with no renewal in sight (Sentinel)
- Vault entries that haven't been accessed since the last schema change (Steward)

The sweep emits a `system:sweep:{officer}` receipt even when nothing is found — the absence of findings is itself an auditable fact.

### 3.3 Output tiers

**Tier 1 — Receipt only (routine):**
Structured chain receipt with finding category, severity, and machine-readable detail. No LLM invocation. No operator notification. The chain is the record.

Receipt event format: `officer:{name}:{category}:{finding_type}`

Examples:
- `officer:std:chain:integrity_verified` — routine chain check passed
- `officer:sen:credential:freshness_ok` — all credentials within rotation window
- `officer:forge:process:inventory_clean` — all registered tools accounted for

**Tier 2 — LLM-reasoned assessment (anomaly):**
When a finding crosses the **significance threshold**, the officer invokes LLM reasoning to produce a signed assessment. LLM calls are expensive; most findings never reach Tier 2. The gate is intentionally strict.

**Significance threshold (all three conditions must hold):**
1. **Count:** 3+ findings of the same type within one sweep window, OR a single finding with `severity >= error`.
2. **Novelty:** The finding type has not already been assessed in the current sweep cycle. One assessment per type per sweep, not one per instance.
3. **Budget:** The officer has remaining LLM budget for this sweep. Default: 2 Tier 2 calls per officer per sweep (configurable in `[officers]`). When budget is exhausted, findings queue for the next sweep. The budget is a hard cap, not a guideline.

The LLM call uses the operator's configured provider and model. The assessment includes the raw findings, the reasoning prompt, and the LLM's analysis. All three land on chain as a single compound receipt.

Examples:
- Steward detects vault schema violations across 5 tools after a bulk migration — one LLM assessment covering all 5, not 5 separate calls
- Sentinel notices 4 gate denials in 60 seconds — one assessment of the cluster
- Forge observes a tool restarting 4 times in 30 minutes — one assessment of the pattern

**Tier 3 — Operator notification (critical):**
Findings that require human attention. The officer emits a Tier 1 receipt with `"notify": true` in the detail payload. The officer does not choose how the notification reaches the operator — that is the cockpit's decision. Any cockpit agent subscribed to the event stream (§3.5) sees the notify flag and surfaces it through its native notification mode: Sage might interrupt the conversation, a visual cockpit might flash a status indicator, a CLI cockpit might print to stderr.

The operator can acknowledge, dismiss, or act. Each response is a signed receipt.

Critical triggers (findings that set `notify: true`):
- Chain integrity violation (Steward)
- Leaked secret detected in chain or logs (Sentinel)
- Sovereign root inaccessible (Sentinel)
- All registered tools unresponsive (Forge)

**Notification backoff and the dismissal signal:** Repeated dismissals are not noise — they are a system signal. An operator dismissing a finding type is the system saying "this heuristic is miscalibrated for this environment." The backoff mechanism is the immediate response; the calibration loop is the structural one.

*Immediate (backoff):* If the operator dismisses 3 consecutive Tier 3 notifications of the same finding type, the officer suppresses further notifications for that type for a configurable cooldown period (default: 24 hours). Findings still emit as Tier 1 receipts — the chain records everything — but `notify` stays `false` during cooldown. The suppression itself is a receipt (`officer:{name}:notify:suppressed`), visible to the operator and overridable. After cooldown, one more notification fires; if dismissed again, cooldown doubles (exponential backoff, capped at 7 days).

*Structural (calibration):* Every suppression receipt feeds directly into the calibration pass (§3.7 Phase B) as a high-weight signal. A finding type that triggers suppression is, by definition, a candidate for threshold adjustment, severity demotion, or check removal. The officer doesn't wait for the next general calibration cycle — a suppression event immediately queues a targeted heuristic adjustment proposal for the next sweep. The dismiss-rate metric in the calibration report (§4.4) weights suppression-triggering types higher than ordinary dismissals. This is how the system learns: operator dismissals are the gradient, the improvement loop is the optimizer, and the chain records the full trajectory.

### 3.4 Cross-domain listening

Each officer subscribes to the others' findings via the chain. An officer can incorporate another's finding into its own assessment but cannot override the owning officer's conclusion.

Example flow:
1. Forge detects tool `ironclaw` restarting repeatedly
2. Forge emits `officer:forge:process:crash_loop_detected`
3. Steward's chain watcher sees the receipt, checks whether the crash loop correlates with vault changes
4. Steward emits `officer:std:vault:no_correlation_with_crash` or `officer:std:vault:recent_change_correlates`
5. Sentinel's chain watcher sees both, checks whether the crash loop correlates with credential expiry
6. If correlated: Sentinel escalates to Tier 3 with a cross-domain assessment

The chain is the communication bus. Officers don't call each other directly — they read each other's receipts. This is store-and-forward (Principle 5) applied to inter-officer coordination.

**Loop prevention:** The chain watcher filters every entry before dispatching to officers. Three rules, applied in order:

1. **Self-skip:** `officer:{this_officer}:*` events are never dispatched to `{this_officer}`.
2. **Depth cap:** Officer receipts carry `cross_domain_depth` (default 0), incremented on each cross-domain reaction. Entries with depth ≥ 2 are dropped. Two hops max.
3. **Dedup window:** One finding per `finding_type` per sweep cycle per officer, regardless of cross-domain input count.

```rust
fn should_dispatch(entry: &ChainEntry, officer: &Officer, cycle: &SweepCycle) -> bool {
    // Rule 1: never dispatch an officer's own receipts back to itself
    if entry.event.starts_with(&format!("officer:{}:", officer.name)) {
        return false;
    }

    // Rule 2: cap cross-domain propagation depth
    if let Some(depth) = entry.detail.get("cross_domain_depth") {
        if depth.as_u64().unwrap_or(0) >= 2 {
            return false;
        }
    }

    // Rule 3: one finding per type per cycle
    if let Some(finding_type) = entry.detail.get("finding_type") {
        if cycle.has_emitted(officer.name, finding_type.as_str()) {
            return false;
        }
    }

    true
}
```

These three rules make infinite loops structurally impossible.

### 3.5 Event stream — cockpit delivery

Authenticated SSE/WebSocket endpoint on `zp serve` (`/api/v1/events/subscribe`). Every chain append emits a typed event. Officers don't know who's listening; cockpits don't know who emitted.

| Layer | What | Role |
|-------|------|------|
| **Chain** | Durable record | Officers append findings. Any agent can walk the chain later. Survives restarts. |
| **Event stream** | Real-time delivery | Each append emits event type, severity, notify flag. Cockpits subscribe with filters (e.g., `officer:* AND severity >= warning`). |
| **Notification** | Tier 3 escalation | `notify: true` flag carried on the stream. Cockpit decides how to surface it (interrupt conversation, flash indicator, print to stderr). |

Authentication: same `ZP-Sig` as gate calls. Only delegated agents can subscribe. New endpoint on the existing HTTP surface — no new process or port.

### 3.6 Security posture score

Computed, chain-anchored metric from the officers' collective output. Tells the operator and the gate whether the system is healthy enough for risk decisions.

#### 3.6.1 Structure

The posture is not a single number. It's three domain scores plus a composite:

| Domain | Officer | Dimensions |
|--------|---------|------------|
| **Integrity** | Steward | Chain integrity (hash linkage valid, no gaps), vault hygiene (% entries passing schema), configuration coherence (config ↔ vault ↔ chain alignment), receipt quality (% receipts passing schema conformance) |
| **Security** | Sentinel | Credential freshness (% within rotation window), delegation health (% active grants valid/unexpired), gate denial rate (inverse of recent denial frequency), identity coherence (all agent registrations match grants), secret hygiene (no plaintext secrets detected) |
| **Operations** | Forge | Process inventory (% registered tools running/responsive), port coherence (allocated = listening), resource headroom (disk/memory within thresholds), launch success rate (recent launches completed) |

Each dimension: **0.0–1.0**. Domain score: weighted average (configurable, uniform default). **Composite: minimum** of three domains — posture is only as strong as its weakest area.

#### 3.6.2 Computation

Recomputed at end of each sweep (after all three officers complete). Staggered sweep order (Steward → Sentinel → Forge) means dimension scores are available before composite. The sweep coordinator emits the composite receipt.

Between sweeps: last-computed value holds. Chain-watch events can trigger advisory updates (`"authoritative": false`), e.g., a chain integrity violation immediately drops integrity to 0.0.

#### 3.6.3 Gate integration (opt-in)

The gate can check posture before granting tool calls:

- `posture_gate_threshold`: minimum composite (default: disabled / 0.0)
- `posture_gate_per_domain`: per-domain minimums (e.g., `security >= 0.5`)

Denial receipts include the full posture breakdown. Operator can override by adjusting thresholds or granting exemptions. Opt-in because a fresh deployment has no sweep history — requiring posture before any tool can run is a chicken-and-egg.

#### 3.6.4 Calibration feedback

Posture feeds the improvement loop (§3.7). A consistently low domain score where the operator isn't acting suggests either too-strict thresholds or unactionable findings. Posture trend over time is a calibration dimension.

Flat-line detection: if all three scores are unchanged for N consecutive sweeps, the coordinator emits `posture:stale` for Steward to investigate.

### 3.7 Self-improvement loop

Before each sweep, officers measure their own accuracy against operator responses. Training data: finding receipts correlated with operator response receipts by ID.

**Calibration metrics** (per sweep, 7-day rolling window): dismiss rate per finding type (>50% = noise), action rate (consistently high = load-bearing), miss rate (operator-filed findings not caught), decay (check went quiet — fixed or broken?), resolution latency (slow response on high-severity = notification path problem).

**Adjustment lifecycle:** Calibration detects drift → officer proposes adjustment (Tier 2, grounded in receipt IDs) → operator approves/rejects → on approval, officer applies and monitors for one sweep window → regression triggers rollback proposal. No autonomous self-modification — every change requires operator signature. If proposals are consistently rejected, the officer reduces proposal frequency.

**Per-officer targets:** Steward calibrates chain walk depth, vault hygiene sensitivity, receipt schema strictness, growth rate thresholds. Sentinel calibrates gate denial clustering, rotation windows, delegation expiry lead time, identity coherence allowlists. Forge calibrates crash loop thresholds (per-tool), health check intervals, port coherence sensitivity, resource headroom levels.

---

## 4. Receipt Schema

### 4.1 Officer finding receipt

```
event: "officer:{officer_name}:{domain}:{finding_type}"
detail: {
    "officer": "std" | "sen" | "forge",
    "tier": 1 | 2 | 3,
    "notify": bool,            // true = cockpit should surface to operator (Tier 3)
    "category": string,        // e.g., "chain", "vault", "credential", "process"
    "finding_type": string,    // e.g., "integrity_verified", "orphan_detected"
    "severity": "info" | "warning" | "error" | "critical",
    "findings": [...],         // structured findings array
    "sweep_id": string | null, // non-null when triggered by periodic sweep
    "trigger": "chain_watch" | "sweep" | "cross_domain",
    "cross_domain_refs": [...], // receipt IDs from other officers that informed this finding
    "cross_domain_depth": number // 0 = original finding, 1 = reaction to another officer, 2 = max (§3.4)
}
```

### 4.2 Officer assessment receipt (Tier 2)

```
event: "officer:{officer_name}:assessment:{category}"
detail: {
    "officer": "std" | "sen" | "forge",
    "tier": 2,
    "finding_receipts": [...],     // receipt IDs of the findings being assessed
    "reasoning_prompt": string,    // the prompt sent to LLM (auditable)
    "assessment": string,          // LLM's analysis
    "model_used": string,          // which model produced the assessment
    "proposed_actions": [...]      // what the officer recommends
}
```

### 4.3 Operator response receipt

```
event: "officer:response:{officer_name}:{finding_type}"
detail: {
    "finding_receipt": string,     // receipt ID being responded to
    "response": "acknowledged" | "dismissed" | "action_taken" | "heuristic_approved" | "heuristic_rejected",
    "action_detail": string | null // what the operator did, if anything
}
```

### 4.4 Calibration report receipt

```
event: "officer:{officer_name}:calibration:report"
detail: {
    "officer": "std" | "sen" | "forge",
    "window_start": timestamp,     // calibration window start
    "window_end": timestamp,       // calibration window end
    "findings_emitted": number,    // total findings in window
    "dismiss_rate": {              // per finding_type
        "{finding_type}": float    // 0.0–1.0
    },
    "action_rate": {
        "{finding_type}": float
    },
    "coverage_gaps": [...],        // manual findings in officer's domain not caught by checks
    "decayed_checks": [...],       // checks with no findings in N cycles
    "proposals_pending": number,   // unresolved heuristic proposals
    "proposals_dismissed": number  // proposals the operator rejected (meta-calibration input)
}
```

### 4.5 Heuristic adjustment proposal receipt

```
event: "officer:{officer_name}:heuristic:proposal"
detail: {
    "officer": "std" | "sen" | "forge",
    "tier": 2,
    "adjustment_type": "threshold" | "severity" | "check_add" | "check_remove" | "trigger_migration",
    "target_check": string,        // which check or finding_type is being adjusted
    "current_value": any,          // current threshold/severity/config
    "proposed_value": any,         // proposed change
    "calibration_receipt": string, // receipt ID of the calibration report that motivated this
    "evidence_receipts": [...],    // specific finding + response receipt IDs grounding the proposal
    "reasoning_prompt": string,    // LLM prompt used to reason about the adjustment
    "assessment": string           // LLM's analysis of why the adjustment is warranted
}
```

### 4.6 Posture score receipt

```
event: "posture:computed"
detail: {
    "authoritative": bool,         // true = sweep-computed, false = advisory mid-sweep update
    "composite": float,            // min(integrity, security, operations) — 0.0–1.0
    "domains": {
        "integrity": {
            "score": float,
            "dimensions": {
                "chain_integrity": float,
                "vault_hygiene": float,
                "config_coherence": float,
                "receipt_quality": float
            }
        },
        "security": {
            "score": float,
            "dimensions": {
                "credential_freshness": float,
                "delegation_health": float,
                "gate_denial_rate": float,
                "identity_coherence": float,
                "secret_hygiene": float
            }
        },
        "operations": {
            "score": float,
            "dimensions": {
                "process_inventory": float,
                "port_coherence": float,
                "resource_headroom": float,
                "launch_success_rate": float
            }
        }
    },
    "sweep_id": string | null,
    "previous_composite": float | null,  // delta tracking
    "trend": "improving" | "stable" | "degrading" | null
}
```

### 4.7 Heuristic applied receipt

```
event: "officer:{officer_name}:heuristic:applied"
detail: {
    "officer": "std" | "sen" | "forge",
    "proposal_receipt": string,    // receipt ID of the approved proposal
    "approval_receipt": string,    // receipt ID of the operator's approval
    "adjustment_type": string,
    "target_check": string,
    "previous_value": any,
    "new_value": any,
    "monitoring_window": string    // how long the officer will monitor for regression
}
```

---

## 5. Implementation Tiers

### Tier 1 — Minimum Viable Cadre (ship first)

The smallest thing that produces value: officers that watch, find problems, and report them as chain receipts.

**Runtime infrastructure:**
- `Officer` trait with scoped read handles (Steward: chain + vault key names; Sentinel: credential metadata + chain + delegation state; Forge: port registry + process table)
- Chain watcher: internal subscriber with pattern-matching dispatch
- Sweep timer: configurable periodic trigger (default 15 min)
- Tier 1 receipt emission only — no LLM calls
- Loop prevention: self-skip, depth cap, dedup (§3.4)
- `[officers]` config section: enable/disable per officer, sweep interval

**Steward checks:**
- Chain integrity (hash linkage, signature verification, gap detection)
- Chain growth rate monitoring
- Vault hygiene (reuse `audit_vault_keys()`)
- Vault schema validation (reuse `validate_tool_env()`)
- Configuration drift detection

**Sentinel checks:**
- Credential freshness
- Gate denial pattern analysis
- Delegation lifecycle monitoring
- Identity coherence verification
- Secret leak scanning (chain entries, log files)

**Forge checks:**
- Process inventory vs registration
- Port coherence (allocated vs listening)
- Launch success monitoring
- Health check pattern analysis
- Composes with Architecture Part VIII Stage 1–2

**Posture score:**
- Per-officer dimension scores computed at sweep end
- Composite = min(integrity, security, operations)
- `posture:computed` receipt emitted each sweep (§4.6)
- Posture API endpoint: `/api/v1/posture`
- Flat-line detection: `posture:stale` if unchanged for N consecutive sweeps

**Event stream:**
- Authenticated SSE on `zp serve`'s HTTP surface (§3.5)
- Cockpit agents (Sage, CLI, etc.) subscribe for real-time findings

### Tier 2 — Make Them Useful (after Tier 1 is stable)

Add reasoning, notifications, and gate integration.

- Tier 2 LLM assessments with significance threshold + budget cap (2 calls/officer/sweep)
- Tier 3 notifications with exponential backoff (ship together — Tier 3 without backoff is noise)
- Posture gate integration (opt-in): `posture_gate_threshold` and `posture_gate_per_domain`
- Calibration reports (§4.4): metrics computed and emitted, but no auto-adjustment proposals yet
- Cross-domain correlated findings → multi-officer Tier 3 escalation

### Tier 3 — Self-Improving System (after Tier 2 is stable)

Officers that learn from their own accuracy.

- Full improvement loop (§3.7): heuristic proposals → operator approval → application → regression monitoring
- Meta-calibration: throttle proposal frequency on consistent rejection
- Quiet sweep mode: single summary receipt per "all clear" cycle (see R3)
- Historical depth tuning: window-based → officer can propose expanding
- Advisory posture updates: mid-sweep chain-watch events updating the score with `"authoritative": false`

---

## 6. Risks

Known risks to address during implementation.

**R1 — Privilege surface.** Officers share `zp-server`'s process memory — read-only constrains writes, not visibility. A bug could leak sensitive data into a finding receipt. Mitigation: scope each officer's read handle to the minimum it needs. Steward: chain entries + vault key names (never secret values). Sentinel: credential metadata + chain + delegation state. Forge: port registry + process table. The `Officer` trait enforces this — each variant receives a scoped read handle, not a reference to the full vault. Secret values must never appear in any finding receipt.

**R2 — LLM cost.** Even with the significance threshold and 2-call budget, a system with many tools and frequent restarts could hit the cap every sweep. At 15-minute sweeps, that's 576 LLM calls/day across the cadre. Mitigation: the budget is configurable, the default is conservative, and the self-improvement loop can propose reducing it further. Monitor actual cost in the first weeks of deployment.

**R3 — Finding receipt volume.** Three officers × 15-minute sweeps × "all clear" receipts = 288 chain entries/day from officers alone, even when nothing is wrong. On a chain that already grows fast, this could be significant. Mitigation: consider a `quiet_sweep` mode where "all clear" sweeps emit a single summary receipt per cycle (one receipt covering all three officers), not one per officer.

**R4 — Poisoned findings.** If a bug causes an officer to emit incorrect findings (e.g., Steward reports chain integrity failure when the chain is fine), the posture score drops, and if gate integration is enabled, tool calls start getting denied. The operator has to diagnose whether the finding or the system is broken. Mitigation: gate posture thresholds should have a manual override, and the posture receipt includes enough dimension detail to quickly identify which officer is the source.

**R5 — Cold start.** On first deployment, officers have no history. Initial thresholds are hand-tuned defaults. Leaning conservative — fewer Tier 2/3 escalations, letting the improvement loop widen over time rather than starting noisy.

---

## 7. Design Principles Applied

| Principle | Application |
|-----------|-------------|
| **Signing is gravity (P1)** | Every finding is a signed receipt. Unsigned observations have no standing. |
| **Identity is a key (P2)** | Officers identified by signing key position in the Genesis hierarchy, not by address. |
| **No center (P3)** | Officers observe local state, emit to local chain. Multi-node = peer receipt exchange. |
| **Every bit counts (P4)** | "All clear" = one receipt, not one per check. |
| **Store-and-forward (P5)** | Inter-officer communication via chain receipts, not function calls. |
| **Tool = intent crystallized (P6)** | Charter IS the implementation constraint. Charter drift is a Steward finding. |
| **Substrate proposes, operator signs** | Officers propose; operators decide. |
| **Posture score (P8 + lsof test)** | Automates the manual health checks an operator would otherwise run by hand. |
| **Self-improvement (§3.7)** | Officers measure their own accuracy and propose adjustments. One level of recursion, operator-gated. |

---

## 8. Open Questions

- **Sweep staggering:** Stagger (Steward → Sentinel → Forge at 5-min intervals) so later officers see earlier findings. Leaning yes.
- **Officer signing keys:** Own keys (Genesis-derived) vs server key. Leaning own — chain should distinguish "Steward found this" from "server appended this."
- **Historical depth:** Window-based vs full-chain walk. Start with window; improvement loop can propose expanding.
- **Quiet sweep mode:** One summary receipt per cycle vs three "all clear" receipts? See R3.
