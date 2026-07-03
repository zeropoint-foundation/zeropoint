# Tool Governance Lifecycle & Nested Observer

**Date:** 2026-07-01 | **Status:** Draft
**See also:** `ARCHITECTURE-2026-04.md`, `SYSTEM-OFFICER-CADRE-2026-06.md`, `SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md`

How tools get brought under ZP governance, how officers evolve from observers to actors, and why Forge works like an immune system. Cartographer's cognitive mode detection is a separate document.

---

## 1. Commitments

**Delegation is universal.** Operators, officers, agents — all receive authority through chain-anchored delegation. The chain doesn't distinguish carbon from silicon. `ActorId` already supports this; what's missing is the capability vocabulary for governance actions (`tool:intake:*`, `tool:harden:*`, etc.). That vocabulary will emerge from what the observer actually needs, not from upfront enumeration.

**Trust is earned, not switched on.** Officers start with zero delegation and accumulate it through accuracy. Three bands: observer (current state), proposer (structured proposals the operator signs), actor (scoped execution without per-action approval). Band 3 is gated on Claim 4 being adversarially verified.

**Governance is observer-driven, immune-system style.** The substrate reads a tool's actual state, diffs it against requirements, and proposes corrections. Hardened tools cost zero compute — the observer deactivates until a state change triggers reactivation.

### What prompted this

The proxy_port 404: IronClaw started outside the governed launch path, the registry wasn't updated, and the operator spent 20 minutes on archaeology that a state-aware observer would have caught in seconds.

---

## 2. Trust Gradient

Read-only remains the default officer posture. Action capability requires explicit chain-signed delegation — same primitive that grants any entity authority. The `Officer` trait and `emit_finding()` are unchanged.

**Band 1 — Observer.** Current state. Emit findings, operator acts manually.

**Band 2 — Proposer.** Emit structured proposals ("set proxy_port to 8091" with the mutation attached). Operator reviews and signs.

**Band 3 — Actor.** Execute within delegated scope. Chain records every action with its authorizing delegation. Operator can narrow or revoke. MUST NOT ship until Claim 4 is adversarially verified — the gate is about proving the enforcement mechanism is sound, not monitoring for widening (which `DelegationChain::verify()` makes structurally impossible).

**Advancement:** Band 1→2: N accurate cycles, low dismissal ratio, operator signs delegation. Band 2→3: N proposals accepted unmodified, operator signs delegation.

**Demotion:** Action triggers a finding from another officer → capabilities suspended pending review. Same delegation primitive.

---

## 3. The Nested Observer

Forge reads a tool's actual state — not just the chain's record of it — and computes the governance delta. The model is immune, not cardiac: activate on change, not on a timer.

### Activation

Hardened tools require zero Forge compute. Forge sleeps until a sensor fires:

| Trigger | Sensor | Mechanism |
|---------|--------|-----------|
| Chain event | `ChainReader` subscription | Event-driven. Already have infrastructure. |
| Port registry change | kqueue `EVFILT_VNODE` on `tool-ports.json` | Event-driven. Trivial. |
| Known tool crash/restart | kqueue `EVFILT_PROC` on registered PID | Event-driven. Register PID when tool enters registry. |
| Vault mutation | Chain receipt from vault write | Event-driven. Piggybacks on chain subscription. |
| Manifest change | kqueue `EVFILT_VNODE` on `.zp-configure.toml` | Event-driven. Same as port registry. |
| New unregistered process | `listeners` crate scan (every ~5min) | Polling — the one piece that isn't event-driven. |

On activation, Forge reads the relevant surfaces, computes the delta, emits a finding or proposal, and goes back to sleep. Empty delta → dormant.

### Sensor layer — rolled our own

We evaluated Apple's Endpoint Security framework (system-wide process events) and Peekaboo (UI automation with app enumeration). Endpoint Security requires an Apple-approved entitlement that takes weeks/months and couples us to their approval process. Peekaboo is pull-based and GUI-app-only — useful for UI inspection, not for process event detection.

The sensor layer is built from three mechanisms, all available without special permissions:

**kqueue `EVFILT_PROC`** — event-driven process lifecycle for known PIDs. Register a tool's PID when it enters the port registry; get immediate notification on exit, fork, or exec. No polling. This covers the majority case: governed tools whose PIDs we already know.

**kqueue `EVFILT_VNODE`** — event-driven file change notifications. Covers `tool-ports.json`, `.zp-configure.toml`, and any other governance-relevant files.

**[`listeners` crate](https://github.com/GyulyVGC/listeners)** — Rust library that maps processes to listening network ports using low-level system APIs. Cross-platform (macOS, Linux, FreeBSD). ~1ms per call on macOS. Replaces `lsof` subprocess spawning with a library call. Used on a slow timer (~5min) solely for discovering new unregistered processes. Once discovered, the new PID gets a kqueue watch and everything is event-driven from there.

The key distinction: four of five sensor types are fully event-driven. The one polling piece (new process discovery) runs a sub-millisecond library call every few minutes — negligible cost, and it's the bridge to event-driven monitoring for each newly-discovered tool.

### What Forge does on activation

| Method | Trigger | Action |
|--------|---------|--------|
| `check_port_coherence` | Port/process change | Compare registry against actual listeners. Propose proxy_port fix. |
| `check_vault_completeness` | Vault/manifest change | Compare manifest schema against vault entries. Propose fills. |
| `check_delegation_coverage` | New tool registered | Check for valid delegation. Propose minimal scope. |
| `check_manifest_accuracy` | Manifest/process change | Compare declarations against observed behavior. Propose corrections. |

### Deactivation

Once hardened and quiescent, Forge deactivates for that tool. Sensors stay registered (cheap). Any sensor fire → reactivate, reassess, resolve or escalate.

### Current gap

Forge today is chain-only: reads `ChainReader`, pattern-matches prefixes, emits findings. It never touches the port registry or process table. Making it a multi-surface observer requires a sensor registration API, extended read handles on the `Officer` trait (or a composed `GovernanceObserver` trait), and wiring `discover_proxy_port` into the activation path. Incremental: one new sensor + surface per phase, starting with port registry file watch.

---

## 4. Governance Posture

A tool's posture is what's currently true, computed from chain evidence. Not a state machine — no required sequence.

| Facet | Evidence |
|-------|----------|
| **Unregistered** | Running, no chain presence. Detected by sensor layer. |
| **Registered** | Manifest hash + port allocation on chain. |
| **Provisioned** | Vault entries validate against manifest schema. |
| **Governed** | Launched via `zp configure exec`, delegation exists, gate evaluating. |
| **Hardened** | All four officers report clean. Forge deactivates. |
| **Delegated-autonomous** | Band 3 delegation. Gated on Claim 4. |

Posture = union of true facets. "Registered + Governed but not Provisioned" is valid — it means vault entries are missing, which Steward or Sentinel would report. Facets gain/drop as evidence appears/degrades. Exception: delegated-autonomous requires explicit operator signature.

### Intake

When the sensor layer detects a new unregistered process:

1. Forge activates, emits `tool:discovered:{name}` with observed attributes
2. Forge proposes a `.zp-configure.toml` from observed behavior
3. Sentinel activates on the discovery receipt, proposes vault entries
4. Cleo activates on the discovery receipt, proposes minimal delegation
5. Operator reviews accumulated proposals, signs, launches via `zp configure exec`
6. Governed launch receipts activate all four officers → each assesses → all clean → hardened → Forge deactivates

Operator involvement: one review-and-sign ceremony. After hardening, zero officer compute until a state change.

---

## 5. Implementation

Each step is useful on its own.

1. **Posture computation.** `governance_posture()` reads the chain, reports true facets. Cache as projection (like PostureScore), invalidate on sensor activation; chain wins on disagreement. Useful for `zp doctor` and `zp ps`.
2. **kqueue file watches.** `EVFILT_VNODE` on `tool-ports.json` + chain event subscription → activate Forge on change. First two event-driven sensors.
3. **kqueue PID watches.** `EVFILT_PROC` on registered tool PIDs. When a governed tool crashes or restarts, Forge knows immediately. Register PID at tool launch, deregister on clean shutdown.
4. **Port discovery.** Add `listeners` crate. Replace `lsof` subprocess with `listeners::get_all()` on a slow timer for new-process detection. Wire `discover_proxy_port` into Forge activation path. Band 1 — finding only.
5. **Deactivation.** All officers clean → mark tool dormant. kqueue watches stay registered (cheap); discovery scan skips known-healthy tools. Any sensor fire → reactivate.
6. **Structured proposals.** Extend Finding (or new Proposal type) to carry actionable mutations. Band 2.
7. **Capability vocabulary.** Define governance scopes in `zp-verbs`, wire into gate.
8. **Officer delegation (Band 2).** Operator grants proposal capabilities via delegation receipts. Band 3 remains gated on Claim 4.

---

## 6. Open Questions

**`listeners` crate — validated.** Tested on APOLLO (2026-07-02). Unprivileged: 20 processes / 87 entries. Root: 30 / 118. The delta is system daemons (launchd, configd, syslogd, mDNSResponder, airportd, kdc, netbiosd) — infrastructure ZP doesn't govern. All user-space tools (IronClaw, ZP server, Comet) are visible without root. No elevated privileges needed for the sensor layer.

---

*Related future work documented elsewhere:*
- *Multi-operator officer delegation (quorum approval for officer capabilities) → `docs/design/quorum-sovereignty.md`*
- *Cartographer × officer cross-observer communication → deferred Cartographer design document*
- *GAR composition (governed agents as tools in this lifecycle) → `docs/design/governed-agent-runtime.md`*
