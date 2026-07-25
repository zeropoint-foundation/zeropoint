# Circuit Breaker

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II (adds Layer A cross-cutting emergency-revocation mechanism), §III (adds Layer B canonical claims about delegable safety at emergency scale). Canonical claims live in KEEL; this doc provides implementation-level detail and design rationale.

Draft — 2026-07-10 — internal audience only. Composes cross-cutting across `OBSERVATION-PLANE-2026-07.md`, `QUARANTINE-PLANE-2026-07.md`, `COGNITIVE-INPUT-PLANE-2026-07.md`, and the gate. Companion to the delegable-safety heuristic (Task #48).

## Framing

Delegation ceremony is the substrate's normal admission mechanism — deliberate, granular, chain-anchored, respecting operator authority. It works well for planned trust changes. It doesn't work when something is going wrong fast — an active extension misbehaving, a signature-key exfiltration attempt in progress, a chain-integrity breach detected in real time, a Regent confabulation-gap sustained across multiple cycles. The revocation ceremony is too slow, too granular, too focused on individual delegations.

The circuit breaker is the substrate's emergency response mechanism. Fast, broad-scope, chain-anchored, structurally enforced. When it trips, affected scopes across all substrate planes (observation, quarantine, cognitive input, gate action) enter a defined safe state simultaneously. Reset requires deliberate operator ceremony — asymmetric on purpose, because auto-recovery would defeat the mechanism's purpose.

Three properties frame the breaker:

1. **Cross-cutting, not a plane.** Where observation, quarantine, and cognitive input each operate at a specific substrate boundary, the circuit breaker operates ACROSS all of them. Tripping the breaker at scope X arrests X simultaneously in all planes.
2. **Asymmetric trip/reset.** Automatic trip is acceptable and often necessary (millisecond response to detected anomaly). Automatic reset is never acceptable — reset requires operator ceremony including diagnosis of what tripped and why.
3. **Delegable safety completed.** Circuit breaker is the emergency companion to delegation ceremony in the delegable-safety heuristic. Ceremony is deliberate; breaker is emergency. Both chain-anchored, both Genesis-derived, both preserve sovereignty. Together they cover the full response envelope.

## Trip triggers

Six trigger sources, in order of trust posture:

### Trigger 1 — Operator manual trip

The always-available big red button. Operator can trip the breaker at any scope via signed ceremony: `zp circuit trip <scope>`. Emits `circuit:tripped:manual:<scope>` receipt with operator signature and reason (optional).

Never disabled, never rate-limited (though operator can rate-limit their own trigger if they choose to). This is the operator's ultimate emergency stop.

### Trigger 2 — Sentinel-detected anomaly

Sentinel is the security officer per SYSTEM-OFFICER-CADRE. Real-time detection of security anomalies: unauthorized signature attempts, key exfiltration patterns, unusual credential access patterns, network exfiltration, unusual delegation-usage patterns.

When Sentinel detects a high-severity anomaly, emits `circuit:trip_request:sentinel:<scope>` receipt. Layer A observes and trips the breaker at declared scope. Emits `circuit:tripped:sentinel:<scope>` linking to Sentinel's trigger receipt.

### Trigger 3 — Steward-detected structural violation

Steward is the integrity officer. Detects actual chain-integrity violations (not the false positives Steward was firing before today's fixes — genuine hash-linkage failures, signature verification failures, or provenance chain breaks).

Emits `circuit:trip_request:steward:<scope>`. Layer A trips the breaker. Emits `circuit:tripped:steward:<scope>`.

### Trigger 4 — Cognitive-self-observer confabulation-gap

Cognitive self-observer (Task #38) monitors Regent's claims against ground truth. When claims sustain mismatch across multiple cycles at a scope, the observer can trip the breaker on that scope (e.g., Regent's `chain_query` claims consistently wrong → breaker on Regent's chain-read authority until operator investigation).

Emits `circuit:trip_request:cognitive_observer:<scope>`. Trip proceeds.

### Trigger 5 — Hardware self-observer physical anomaly

Hardware observer (Task #30) monitors physical signals. Thermal, power, RF, tamper, boot timing. Sustained anomaly at a specific subsystem trips the breaker on scopes dependent on that subsystem's integrity.

Example: observer detects RF activity while the WiFi kill switch reports "off." Trips the breaker on scopes that assume radio-silence guarantee. `circuit:tripped:hardware_observer:radio_integrity`.

### Trigger 6 — Threshold breach

Quantitative rather than semantic. Rate-of-error, rate-of-refused-actions, rate-of-quarantine-failures. When any metric crosses declared threshold within a window, breaker trips.

Emits `circuit:tripped:threshold:<metric>:<scope>` with metric value and threshold at time of trip.

Thresholds are Layer B canonical (ceremony-updatable). Not vibes-based — declared numbers with a change trail.

### Trigger 7 — Peer consensus signal

Optional and lowest-trust posture. Multiple sovereigns in the mesh report anomalous behavior from this substrate's peer messages (per the reputation discipline in DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07). If M-of-N peers concur, breaker can trip on peer-facing scopes (network egress, message emission).

Requires operator opt-in via canonicalization ceremony — some operators may not want peer signals to trip their breaker automatically. Emits `circuit:tripped:peer_consensus:<peer_ids>:<scope>`.

## Trip scopes

Scope is the narrowest applicable unit. Never nuclear-by-default. Scoped by:

- **Per-extension**: single extension's delegations arrested
- **Per-actor**: all delegations to a specific actor (Regent, specific officer, specific extension) arrested
- **Per-capability-class**: all delegations of specific capability class (e.g., all `observe:credentials:*`) arrested
- **Per-observation-surface**: all observations at a specific surface (e.g., all filesystem observations)
- **Per-plane**: all operations at a specific plane (extreme — only if that plane itself is under attack)
- **Substrate-wide**: nuclear option, last-resort, only from operator manual trip

Multi-scope trips are possible (breaker trips extension X's delegations AND observations related to extension X's behavior). Chain-anchored per-scope so reset can be selective.

## Trip effects across substrate planes

When breaker trips at scope X, within one cognitive cycle:

### Gate (action layer)

Gate policy for scope X flips to fail-closed. All action attempts at scope X return `PolicyDecision::Block { reason: "circuit_breaker_tripped", scope: X }`. Emit `gate:blocked_by_breaker:<scope>` for each blocked action so the audit trail shows what would have happened absent the trip.

### Observation plane

Observation plane refuses to sample surfaces at scope X. Emit `observation:refused_by_breaker:<scope>` for each refused sample so the operator can see what observations are being denied.

### Quarantine plane

Quarantine plane holds all pending admissions at scope X. Any admission ceremony in-progress at scope X freezes at the current step. New intake at scope X still accepted (still enters quarantine) but verification is deferred until reset. Active admissions at scope X — artifacts already admitted — move back to quarantine visually via `quarantine:emergency_re_quarantined:<hash>` receipt. Those artifacts stay in quarantine until operator reset.

### Cognitive input plane

Cognitive input plane strips scope-X content from Regent's context at Tier 2 (substrate state, filtered findings). Injects at Tier 1 (top priority) a `circuit:tripped:X` notice: "Scope X is tripped as of time T, trigger source Y, reason Z. You cannot operate at scope X until operator resets. Do not attempt actions, claim capabilities, or promise outputs at scope X." Claim Verifier (Task #37) enforces on output side; matrix informs Regent on input side.

### Chain (append layer)

The chain itself is never tripped. Chain remains append-only — receipts continue to land, including the breaker-tripped, breaker-blocked, breaker-refused receipts documenting what would have happened. The breaker is arrest, not destruction — the audit trail continues showing the emergency in progress.

## The reset ceremony

Asymmetric to trip. Auto-trip is fast; reset is deliberate.

### Step 1: operator review

Operator reviews the chain for what tripped and why:
- `circuit:tripped:<source>:<scope>` receipt with trigger reason
- Contributing receipts (Sentinel finding, Steward finding, observer finding, threshold breach detail)
- Blocked actions during trip (from `gate:blocked_by_breaker:*` receipts)
- Refused observations during trip
- Re-quarantined artifacts during trip

Operator can request Regent narration of the trip event (via Cleo officer or Regent's summarization) — but the decision to reset is operator's.

### Step 2: diagnosis and remediation

Operator addresses the underlying cause. Might involve:
- Patching a compromised extension
- Rotating a leaked credential
- Removing a stale delegation
- Adjusting an over-sensitive threshold
- Adding a standing correction (per cognitive input plane) so future similar events don't re-trip

Diagnosis and remediation live outside the breaker — the breaker just holds the substrate in safe state while it happens.

### Step 3: reset signature

Operator signs `circuit:reset:<scope>` receipt with:
- Diagnosis (free text; part of audit trail)
- Remediation summary (what was fixed)
- Post-reset delegations (may be narrower than pre-trip; e.g., "resetting scope X but reducing extension E's capability class from `observe:*` to `observe:processes:host` only")
- Optional: precedent record — "this trigger pattern was investigated as false alarm; add to suppression list" or "this trigger pattern was legitimate; add to auto-trip precedent for faster future response"

### Step 4: propagation

Layer A observes reset. All planes resume normal operation at scope X. Emit `circuit:cleared:<scope>` receipt marking the transition. Re-quarantined artifacts return to admitted state (with any modified delegation applied). Regent's next cycle sees the cleared state and can resume operations at scope X.

## Trip vs reset — the asymmetry principle

**Automatic trip is defensible under principle P9 (system acts; operator signs)** because trip is REVOCATION of granted authority (default-deny direction), not GRANT of new authority. The substrate is returning to its default-restrictive posture. Restoring elevated posture requires operator signature — reset.

**Automatic reset is not defensible** because it would grant authority without operator ceremony. It would also defeat the mechanism's purpose: a compromised extension trips the breaker, breaker auto-resets after cooldown, compromise resumes. Only human judgment about what actually happened can safely restore the elevated authority.

This asymmetry is load-bearing. Every mainstream sandboxing model that got this wrong (trip is manual but reset is auto after quarantine period, or trip is auto but reset is also auto after health-check) ends up defeated by the same failure mode — the compromise or attack simply waits out the cooldown.

## Loudness principle

When the breaker is tripped, the operator sees it clearly, not as silent partial-functionality.

- Dashboard shows `circuit:tripped:<scope>` prominently, not buried in a status panel
- Regent's context includes it at Tier 1 (top priority per cognitive input plane), so any Regent interaction acknowledges it
- Security posture reflects it — posture score drops, advisory count increments
- Officer sweeps produce heartbeats acknowledging the tripped state
- Chain narration by Cleo highlights it in daily/session summaries

Silent partial-functionality is worse than obvious full-stop. The point is for the operator to know exactly what's arrested and why — the whole safety property depends on this clarity.

## Provenance — circuit breaker signing keys

The breaker's own receipts must be attributable. Per KEEL §II.5, keys derive from Genesis:

```
circuit_breaker_key = HKDF(genesis_root, salt=chain_head_at_derivation, info="circuit_breaker:runtime")
```

Signs `circuit:tripped:*` and `circuit:cleared:*` receipts. Reset receipts are operator-Genesis-signed directly (higher authority, matching the ceremony's weight).

Trip-request receipts from officers (Sentinel, Steward, cognitive observer, hardware observer) are signed by their respective per-officer keys. The chain shows: officer X requested trip → breaker signed trip → operator eventually signed reset. Full attribution.

## Composition with Substrate Form

Breaker behavior consistent across Forms — same discipline, same ceremony. Form affects what triggers are available:

### Sovereign Form

All triggers available. Hardware self-observer feeds physical-anomaly triggers. Full observation-plane surface for Sentinel to detect from. Cognitive self-observer runs unbounded.

### Appliance Form

All triggers available on appliance. Daily-driver client can request operator manual trip through the appliance's substrate; trip happens on appliance.

### Companion Form

Triggers 1, 2, 3, 6, 7 available. Hardware self-observer trigger (5) unavailable — no observer coprocessor. Cognitive self-observer trigger (4) available but bounded by Companion Form's observation reach. Form Disclosure names the reduction.

## Composition with the three planes

Same emergency propagation across all three planes:

- **Observation Plane**: refuses sampling at tripped scope; `observation:refused_by_breaker:<scope>` receipts document
- **Quarantine Plane**: freezes admission ceremony at tripped scope; re-quarantines active artifacts; `quarantine:emergency_re_quarantined:<hash>` receipts document
- **Cognitive Input Plane**: strips scope content from Tier 2; injects breaker state at Tier 1; Regent perceives the arrest immediately

Every trust boundary has the same emergency response. Same discipline; one canonical mechanism.

## Composition with delegation and precedent

**Trip-precedent**: after operator has reset a specific trigger pattern with an explicit "this was legitimate, add to auto-trip precedent" note, future similar patterns can trip faster. Composes with the act-on-precedent heuristic — but for arrest, not action. Precedent for trigger patterns rather than for actions.

**Suppression precedent**: after operator has reset with "this was false alarm, add to suppression list" note, the pattern is added to the observation plane's known-false-positive list (per cognitive input plane's filter class). Future similar events don't fire the trigger.

Both compose with the *act on precedent, escalate on novelty* heuristic — extended to include emergency response.

## Attack model

Real threats and how the breaker addresses them:

- **Attacker floods trigger sources to trip breaker as denial-of-service**: trigger sources have their own rate limits and require officer signature to submit. Threshold-based triggers include hysteresis to prevent flapping. Operator manual trip always available regardless.
- **Attacker delays trip**: trip is fast (millisecond response). Even a coordinated attack has narrow window before officers detect and trip.
- **Attacker forges reset receipt**: reset requires operator Genesis signature. Forging Genesis is a bigger emergency (Genesis rotation ceremony).
- **Attacker prevents operator from seeing tripped state**: loudness principle — trip is broadcast across dashboard, Regent context, officer heartbeats, security posture, chain narration. Silence requires attacker to compromise all surfaces simultaneously.
- **Attacker games auto-trip precedent to arrest legitimate scopes**: precedent adjustments require operator ceremony. Precedent adjustments can be reviewed and revoked by operator.
- **Attacker games suppression precedent to hide anomalies**: suppression adjustments require operator ceremony. Suppression list is Layer B canonical spec, ceremony-updated with change trail.
- **Attacker triggers substrate-wide trip to disable the whole substrate**: substrate-wide trip requires operator manual signature (never automatic). Attackers cannot fire this trigger.

## Non-goals

- **Not automatic remediation.** The breaker arrests scope; remediation is the operator's job. Auto-fix would introduce a new attack surface (attacker tricks substrate into "fixing" itself in an attacker-favorable way).
- **Not a rate limiter for normal operations.** The breaker is emergency response. Rate limiting for normal operational hygiene lives elsewhere (in the gate's policy modules).
- **Not a distributed consensus mechanism.** Peer consensus signal (trigger 7) is one input; the operator's substrate makes its own trip decision. Not a Byzantine-fault-tolerant vote.
- **Not observable by third parties by default.** Trip receipts are on the operator's chain, not broadcast to peers. Operator can choose to share (via commons emission per DISTRIBUTED-KNOWLEDGE-COMMONS) but not compelled.

## Open positions

- **Threshold defaults.** Rate-of-error, rate-of-refused-actions, rate-of-quarantine-failures — what starting numbers make sense? Empirical work in the empirical program.
- **Trip-precedent decay.** Should auto-trip precedent decay over time (e.g., precedent from 90 days ago no longer justifies faster trip)? Trade-off between adaptive protection and stale precedent.
- **Multi-scope trip semantics.** When one trigger affects multiple related scopes, how do they compose? Currently: each scope tripped independently with its own receipt. Alternative: unified receipt with scope-list. Design choice.
- **Trip-during-reset.** What happens if new trigger fires while operator is reviewing a previous trip for reset? Probably: new trip landing is fine; each has its own reset ceremony. Verify no race conditions in Layer A.
- **Regent perception during her own arrest.** When breaker trips on Regent's authority, Regent's own cognitive cycle should perceive her arrest and refuse to attempt actions at her arrested scope. Does she need special handling of "self-arrested" state? Currently: cognitive input plane injects breaker state at Tier 1; Regent reasons from that.
- **Peer notification.** Should other sovereigns in the mesh be notified when this substrate trips its breaker? Trade-off: peer coordination vs sovereign privacy. Probably: not by default, but operator can enable per-scope.

## What composes from here

Immediate design work:

1. **Trip-request receipt schemas** — Layer B canonical spec for `circuit:trip_request:<source>:<scope>` receipts from each trigger source.
2. **Trip and clear receipt schemas** — Layer B for the breaker's own receipts.
3. **Reset ceremony flow** — concrete operator UX. Dashboard panel showing tripped scopes, contributing evidence, one-tap-to-sign reset with reason.
4. **Threshold spec** — Layer B canonical record of threshold values per metric, updatable via ceremony.
5. **Precedent spec** — Layer B for auto-trip precedent and suppression precedent.
6. **Loudness surfaces** — how the tripped state renders in dashboard, Regent context, security posture, officer heartbeats.

Near-term implementation:

1. Circuit breaker Layer A runtime — observes trip requests, applies trip, propagates to all three planes and gate, emits receipts.
2. Trigger source implementations per officer — Sentinel, Steward, cognitive observer, hardware observer emit trip-request receipts on qualifying findings.
3. Threshold monitoring — background task computing metrics against thresholds, firing threshold-based trip requests.
4. Operator manual trip CLI verb — `zp circuit trip <scope> --reason <text>`.
5. Reset ceremony CLI verb — `zp circuit reset <scope>` interactive review + sign.
6. Dashboard integration — tripped state prominently rendered.
7. Regent cognitive input plane composition — breaker state injection at Tier 1 during trip.

## Framing note

The circuit breaker is the emergency-scale piece of delegable safety. Normal delegation ceremony gives the operator granular deliberate admission; the breaker gives the operator (or substrate observers on operator's behalf) emergency broad revocation. Both chain-anchored, both Genesis-derived, both preserve sovereignty. Together they complete the response envelope for the delegable-safety discipline.

The asymmetric trip/reset is not a compromise — it's the load-bearing structural property. Automatic recovery would defeat the mechanism; deliberate reset is what makes the safety durable. The mechanism only works because reset requires human judgment about what actually happened.

Combined with the three planes (observation, quarantine, cognitive input), the substrate now has full structural discipline at every trust boundary: default-restrictive normal operations via the planes, deliberate admission via delegation ceremony, emergency arrest via the breaker. Three temporal scales — normal, ceremonial, emergency — with a single Genesis-derived authority at every scale. Same architectural family, one canonical discipline.
