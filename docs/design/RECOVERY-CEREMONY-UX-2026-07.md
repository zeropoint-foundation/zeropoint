# Recovery Ceremony — Operator UX

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis quorum), §III.20 (forward-only recovery), and Part XI (Genesis ceremony). Specifies the operator experience of the substrate's recovery ceremonies — M-of-N Genesis recovery, forward-only substrate recovery, post-emergency reset, and Form-graduation recovery. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `GENESIS-ROTATION-CEREMONY-2026-07.md` (rotation is one recovery pathway), `BLAST-RADIUS-AND-RECOVERY-2026-07.md` (forward-only recovery discipline), `CIRCUIT-BREAKER-2026-07.md` (post-escalation reset ceremonies), `SUBSTRATE-FORM-2026-07.md` (Form-specific recovery paths).

## Framing

Recovery ceremonies are the operator's most consequential interactions with the substrate. They typically happen at moments of stress — Genesis compromise, hardware failure, discovered anomaly, emergency escalation. Poor UX at these moments is not just inconvenient; it can produce cascading errors that turn recoverable situations into unrecoverable ones. UX design for recovery ceremonies is therefore load-bearing safety design, not surface polish.

Three properties frame the UX:

1. **Recovery UX is designed for high-stress moments.** Not "operator learns this at leisure" but "operator invokes this because something is wrong, may be under time pressure, may have partial information." UX must be legible under stress.
2. **Recovery UX is chain-anchored, not app-anchored.** Every step of ceremony emits chain receipts. Operator can walk away, come back later, resume from chain state. UX is a projection of chain state, not an ephemeral wizard.
3. **Recovery UX is delegable to Regent narration but authorized only by operator ceremony.** Regent can guide operator through recovery ("next step is verifying peer trust anchors; review here"), but every consequential step requires operator ceremony (Genesis-derived signature). Regent proposes; operator signs.

## The four recovery ceremony categories

### Category 1 — Genesis recovery (M-of-N)

**Trigger**: operator has lost Genesis material. Cannot sign forward with old Genesis; needs to invoke recovery quorum.

**Prerequisites**: operator has pre-registered N recovery tokens per Decision A. M of them are currently accessible.

**Ceremony scope**: substantial — brings up a new Genesis, transitions all substrate-critical state to new Genesis (composes with Genesis rotation ceremony).

**Time pressure**: variable. Compromise-driven recovery is urgent; lost-token recovery may be planned.

### Category 2 — Forward-only substrate recovery

**Trigger**: circuit breaker escalated to substrate-wide response; substrate is in degraded state; operator invokes recovery.

**Prerequisites**: chain is intact (chain is truth per III.20). Some derived state may be corrupt or missing.

**Ceremony scope**: moderate — reconstruct derived state from chain snapshots, verify subsystems, exit degraded mode.

**Time pressure**: high — substrate is degraded until recovery completes.

### Category 3 — Post-emergency reset

**Trigger**: after circuit breaker escalation, before returning substrate to full operation, operator ceremony authorizes reset.

**Prerequisites**: escalation events chain-anchored; forensic investigation complete or acknowledged incomplete.

**Ceremony scope**: light — signed acknowledgment of what happened and why continuation is authorized.

**Time pressure**: bounded — substrate remains in reduced-authority mode until reset ceremony completes.

### Category 4 — Form-graduation recovery

**Trigger**: substrate moving between Forms (Companion → Appliance → Sovereign, or reverse). Recovery in the sense of re-establishing full trust chain at new Form.

**Prerequisites**: operator has provisioned new hardware / Form target; peer notification protocols configured.

**Ceremony scope**: substantial — involves Form-specific hardware Genesis provisioning, delegation cascade, peer notification.

**Time pressure**: none — planned operation.

## UX principles

### Principle 1 — Every ceremony step is chain-anchored

Operator can leave the UX mid-ceremony and return later. State lives on chain, not in a wizard. Dashboard shows current ceremony state as projection of chain.

Not: "Step 3 of 7 — clicking next takes you to Step 4."
Yes: "Chain says: ceremony `<id>` at Phase 2 (transition receipts pending)."

Operator invokes ceremony action → substrate emits receipt → dashboard reflects new chain state.

### Principle 2 — Regent narration is advisory; ceremony is authoritative

Regent explains what's happening, why, and what step comes next. But Regent cannot execute ceremony steps on operator's behalf — every consequential step requires operator hardware token touch (Sovereign Form) or operator-authenticated ceremony (Companion Form).

Not: "Regent, please rotate my Genesis."
Yes: "Regent, walk me through Genesis rotation. I'll sign each step."

### Principle 3 — Impact is visible before authorization

For every step requiring operator ceremony, the substrate presents:
- What this step does
- What is preserved (chain history, precedent, identity)
- What changes (current authority, active delegations, derived state)
- What can be undone (nothing after chain-anchored — but operator sees this clearly)

Operator sees consequences before signing. No surprise transitions.

### Principle 4 — Recovery does not silently lose data

Chain is preserved. Historical signatures remain valid. Precedent accumulated under old Genesis carries forward. Ceremony receipts record what changed, when, and why. Operator can audit later.

If any recovery step *would* discard data, UX surfaces it explicitly and requires additional confirmation.

### Principle 5 — Degraded mode is legible

While in degraded / reduced-authority mode, operator sees clearly:
- What authority is active
- What authority is suspended
- What the substrate can and cannot do
- What ceremony steps are required to exit degraded mode

Not opaque "system unavailable." Explicit "recovery ceremony `<id>` at Phase 2 of 4; awaiting operator signature on transition receipts."

## The Genesis M-of-N recovery ceremony UX

**Trigger surface**: operator invokes `zp recovery genesis` CLI or dashboard "Recovery" panel.

**Phase 1 — Recovery declaration**

Substrate presents to operator:
- Current chain state summary (last authoritative Genesis-derived receipt, timestamp)
- Recovery threshold (M of N, e.g., 2 of 3)
- List of pre-registered recovery tokens

Operator confirms recovery is needed. Emits `recovery:genesis:declared:<recovery_id>` receipt via any authority currently available (recovery quorum share on any recovery token can initiate declaration).

**Phase 2 — Quorum gathering**

Substrate presents:
- Current quorum status: "0 of M shares present"
- List of recovery tokens with status (present / not connected)
- Instructions per remaining share

For each share operator connects:
- Substrate detects token
- Prompts for physical interaction (touch YubiKey / Nitrokey / Trezor)
- Verifies signature
- Emits `recovery:genesis:share_received:<recovery_id>:<share_id>` receipt
- Updates quorum status: "1 of M", "2 of M", etc.

When M shares are received:
- Substrate combines shares
- Emits `recovery:genesis:quorum_complete:<recovery_id>` receipt

If quorum cannot be reached (only K < M shares available):
- Substrate presents clear status: "insufficient shares — cannot proceed"
- Operator options: (a) find additional shares, (b) accept substrate as read-only from this point

**Phase 3 — New Genesis provisioning**

Substrate presents:
- Options for new Genesis: existing hardware token (import), fresh hardware token, software fallback
- Consequences of each option (Form implications, peer notification implications)

Operator selects. Substrate:
- Guides operator through new-token provisioning
- Verifies new Genesis public key
- Emits `recovery:genesis:new_key_provisioned:<recovery_id>` receipt signed by recovery quorum bridging signature

**Phase 4 — Transition and handover**

Substrate presents the transition receipts that will be signed:
- Vault re-encryption transition
- Delegation cascade transition
- Officer / observer / cognitive key reprovisioning transitions

For each transition, operator signs via new Genesis token. Substrate emits corresponding transition receipts.

Culminating handover receipt: signed by both recovery quorum AND new Genesis. Substrate emits `recovery:genesis:handover_completed:<recovery_id>` receipt.

**Phase 5 — Verification**

Substrate self-verifies: all active delegations trace to new Genesis; vault decrypts with new keys; officer signatures verify; observers heartbeat under new Genesis.

Dashboard shows verification progress in real time. On success: `recovery:genesis:completed:<recovery_id>` receipt.

**Post-ceremony**: peer notification distribution per Peer Trust Anchor mechanism.

## The forward-only substrate recovery UX

**Trigger surface**: operator invokes recovery after circuit breaker escalation or after observed substrate degradation.

**Phase 1 — Damage assessment**

Substrate presents:
- Chain integrity status (chain-tail verification result)
- Derived state status (what's present, what's missing, what's suspect)
- Recent escalation events (if any)
- Health of subsystems (officers, observers, cognitive layer)

Regent narrates: "Substrate entered degraded mode at time T because escalation event E. Current impact: capability X reduced-authority; derived state Y missing; subsystem Z requires reprovisioning."

**Phase 2 — Recovery plan review**

Substrate proposes recovery plan:
- Steps to reconstruct derived state from chain snapshots
- Steps to reprovision degraded subsystems
- Steps to exit degraded mode

Operator reviews. Each step surfaces impact clearly. Operator can skip steps that don't apply or add manual steps.

**Phase 3 — Step execution**

For each step, operator signs authorization receipt via Genesis. Substrate executes step, emits completion receipt, moves to next step.

Steps are chain-anchored — operator can pause, review chain state, resume later.

**Phase 4 — Verification and exit**

After all steps complete, substrate self-verifies health. On success: `recovery:substrate:completed:<recovery_id>` receipt. Substrate exits degraded mode.

If verification fails on any step, substrate remains in degraded mode; operator can investigate.

## The post-emergency reset UX

**Trigger surface**: after circuit breaker escalation events, dashboard surfaces "Escalation active — reset ceremony required."

**Phase 1 — Escalation review**

Substrate presents:
- Escalation event(s) with full context
- Root cause analysis (from officer investigations)
- Mitigation actions taken
- Substrate's current state (what capability is available)

Regent narrates the incident timeline.

**Phase 2 — Investigation acknowledgment**

Operator reviews findings. Options:
- Accept root cause and continue (emit `recovery:reset:root_cause_accepted:<incident_id>` receipt)
- Reject and require further investigation (substrate remains in reduced-authority; investigation continues)
- Escalate to broader ceremony (Genesis rotation, peer notification, etc.)

**Phase 3 — Reset authorization**

If operator accepts, they sign `recovery:reset:authorized:<incident_id>` receipt via Genesis. Substrate exits reduced-authority mode. Circuit breaker resets to normal state.

Substrate emits `recovery:reset:completed:<incident_id>` receipt.

## The Form-graduation recovery UX

**Trigger surface**: operator initiates via `zp form graduate <target_form>`.

**Phase 1 — Graduation planning**

Substrate presents:
- Current Form
- Target Form
- Steps required (new hardware provisioning, chain migration, peer notification)
- Timeline estimate
- Rollback options

Operator reviews. Confirms plan.

**Phase 2 — Target Form preparation**

Substrate guides operator through target-Form-specific prep:
- Sovereign Form: hardware Genesis provisioning, TPM/PCR setup, boot chain verification
- Appliance Form: dedicated hardware pairing, Genesis-signed pairing ceremony
- Companion Form: vendor OS integration, key generation within vendor scope

**Phase 3 — Chain migration**

Substrate copies chain to target Form's storage. Emits `form:graduation:chain_migrated:<graduation_id>` receipt.

**Phase 4 — Delegation cascade**

Active delegations re-signed under target Form's Genesis (may be same Genesis if hardware token graduates with the operator; may be new Genesis if hardware is being provisioned).

**Phase 5 — Handover**

New Form takes authoritative control. Old Form's substrate emits final `form:graduation:handover_completed:<graduation_id>` receipt. Optionally: old Form's substrate transitions to observer / archival mode.

**Phase 6 — Peer notification**

Federated substrates notified of Form graduation. Peer trust anchor updates as needed.

## Dashboard surfaces

Recovery UX manifests across three dashboard surfaces:

### The Recovery Panel

Persistent panel in dashboard. Content varies by state:

**Steady state**: "No recovery ceremony in progress. Substrate operating normally."

**In-progress recovery**: shows ceremony ID, phase, next required action, receipts emitted so far.

**Degraded mode**: shows what capability is available, what's suspended, ceremony required to exit.

### The Emergency Panel

Surfaces when circuit breaker escalation is active. Shows escalation events, mitigation status, and ceremony required to return to normal.

Emergency Panel is louder than Recovery Panel — visual signals that operator attention is needed now.

### The Ceremony History Panel

Historical view of past recovery ceremonies. Chain-anchored, immutable. Operator can review any past ceremony in detail.

Serves as learning corpus — operator sees prior recoveries and how they resolved.

## CLI verbs

Recovery CLI is symmetric with dashboard:

- `zp recovery status` — current recovery state
- `zp recovery genesis` — initiate Genesis M-of-N recovery
- `zp recovery substrate` — initiate forward-only substrate recovery
- `zp recovery reset` — initiate post-emergency reset
- `zp form graduate <target>` — initiate Form graduation
- `zp recovery history` — list past recovery ceremonies
- `zp recovery detail <ceremony_id>` — view specific ceremony detail

Every verb produces chain-anchored effects. Verbs are advisory-safe (calling `zp recovery status` is always safe); action verbs require explicit operator ceremony.

## Regent's role in recovery

Regent narrates recovery ceremonies. She cannot execute them.

Regent contribution:
- Explaining what's happening in operator-legible language
- Walking operator through next steps
- Answering questions about what specific receipts mean
- Cross-referencing recovery history for pattern recognition ("Last time you recovered from this class of escalation, root cause was...")
- Flagging concerns ("This recovery step will change delegation state; you may want to review active delegations first")

Regent cannot:
- Sign recovery receipts on operator's behalf
- Execute Genesis operations without operator hardware token
- Skip steps
- Approve reset without operator ceremony

Regent's advisory role is scoped by cognitive delegation. Standard delegation gives Regent narration + advisory; broader delegation could give Regent more autonomy in low-consequence recovery steps (per act-on-precedent heuristic), but Genesis-consequential ceremony always requires operator ceremony.

## Attack model

Attacker scenarios affecting recovery UX:

- **Attacker tricks operator into false recovery**: attacker convinces operator to run recovery ceremony that transitions authority to attacker. Mitigation: ceremony steps chain-anchored, operator sees each step's consequence before signing, hardware token requires physical touch.
- **Attacker manipulates dashboard to hide critical information**: attacker controls display layer. Mitigation: chain-anchored ceremony state can be verified via independent CLI, hardware Regent (if hardware observer is trusted), or peer inspection.
- **Attacker races operator during recovery**: attacker submits their own recovery ceremony receipts simultaneously with operator's. Mitigation: chain-anchored ordering, race resolution favors first-authorized receipt, recovery quorum thresholds prevent single-share hijacking.
- **Attacker delays recovery by DoS**: attacker prevents recovery from completing (network partition, resource exhaustion). Substrate remains in degraded mode until recovery completes. Operator has options for out-of-band ceremony (physical device access, local ceremony).
- **Attacker exploits partial recovery state**: attacker acts during ceremony pause. Substrate in-ceremony has reduced authority; capability during ceremony is bounded to prevent attacker action.

## Failure modes

- **Operator abandons ceremony mid-flow**: chain state preserves progress. Ceremony can be resumed. Substrate remains in transitional state. Warning surfaces after time threshold.
- **Ceremony deadlock (insufficient quorum, insufficient authority)**: substrate cannot proceed. Operator sees clear status. Options for out-of-band resolution (adding recovery tokens, invoking peer assistance).
- **Verification fails at ceremony conclusion**: substrate identifies which subsystem verification failed. Operator can retry, investigate, or escalate to broader ceremony.
- **Operator makes wrong choice in ceremony**: e.g., accepts root cause that turns out to be incorrect. Chain preserves the record; operator can invoke follow-up ceremony to correct. Wrong choice is not silent; chain shows what was chosen and when.
- **Regent narration is wrong**: Regent explains ceremony step incorrectly. Cognitive Self-Observer may flag; operator can verify directly via chain state; ceremony steps themselves have canonical descriptions independent of Regent narration.

## Non-goals

- **Not a substitute for backup**. Recovery is for legitimate scenarios where authority or state needs to transition. Not for "I forgot my password; give me my substrate back." Genesis loss without recovery quorum is unrecoverable; that's structural, not a UX issue.
- **Not automatic self-repair**. Substrate does not autonomously recover from arbitrary problems. Recovery requires operator ceremony. Automation is limited to guidance and reconstruction of chain-anchored state.
- **Not universal remedies**. Different escalation causes require different ceremonies. UX guides operator to correct ceremony but does not shoehorn all recovery into one path.
- **Not stress-free**. Recovery ceremonies happen at consequential moments. UX aims to reduce cognitive load, not to hide consequences.

## Open positions

- **Ceremony pause and resume UX**. How long can ceremony be paused before it's considered abandoned? What happens to derived state during pause?
- **Multi-device ceremony coordination**. Recovery ceremony spans devices: quorum shares on multiple devices, cross-device state migration. Choreography design.
- **Assistive ceremony walkthroughs**. Should there be a "walk me through this" mode where Regent proactively guides step by step? Or is operator-initiated pull the right model?
- **Ceremony rehearsal mode**. Practice recovery ceremony without producing chain-anchored effects? Educational aid; safety concern (does it create false confidence?).
- **Time pressure indicators**. When recovery is urgent (compromise-driven), how does UX communicate urgency without inducing panic-driven errors?
- **Peer-assisted recovery UX**. If operator engages peers to help verify recovery legitimacy, how do peer signals surface in operator UX?
- **Cross-ceremony coordination**. When multiple ceremonies are in flight (rotation + Form graduation + post-emergency reset), how does UX manage complexity?

## What composes from here

Immediate design work:

1. **Ceremony state schema** — chain-anchored ceremony progress state
2. **Recovery panel component** — dashboard surface for recovery state
3. **Emergency panel component** — separate surface for active escalations
4. **Regent narration contract** — how Regent narrates ceremony steps, what she can and cannot claim
5. **Verification presentation** — how post-ceremony verification results surface to operator

Near-term implementation:

1. Recovery panel runtime in `crates/zp-server/src/dashboard/recovery/`
2. Chain-anchored ceremony state manager
3. Ceremony pause / resume logic
4. Regent narration integration with cognitive input plane
5. CLI verb: `zp recovery status|genesis|substrate|reset|history|detail`
6. Post-ceremony verification runner with per-subsystem checks

## Framing note

Recovery ceremony UX is the operator's most consequential interaction with the substrate. Designed for high-stress moments; chain-anchored (not app-state-anchored); Regent-narrated but operator-authorized; consequences visible before ceremony; degraded modes legible; no silent data loss.

The load-bearing insight: **UX at the moment of stress is safety design, not surface polish.** A confusing recovery UX at 3am after Genesis compromise can turn a recoverable scenario into a permanent loss. A clear UX preserves operator agency, keeps the chain intact, and produces recovery ceremonies whose consequences the operator can inspect after the fact.

Combined with the substrate's structural discipline across every trust boundary — actions, admissions, observations, cognition, extensions, hardware, emergency response, Genesis rotation, peer trust, build lifecycle, reproducibility ceremony — recovery ceremony UX completes the operational envelope for the substrate's own most consequential moments. What today's incidents surfaced (partial state, invisible degradation, silent stale files) becomes structurally visible when the recovery surfaces are chain-anchored projections and Regent's narration is bounded to advisory scope. Sovereignty is preserved because operator authorizes; safety is preserved because ceremony is chain-anchored; continuity is preserved because chain is truth across every recovery pathway.
