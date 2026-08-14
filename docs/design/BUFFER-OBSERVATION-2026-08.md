# Buffer Observation — Prospective Declaration of Depleting Reserves

**Document type:** Design note. Names one active reserve the substrate does not measure, pre-declares four whose preconditions do not yet exist, and records why eight prior candidates were cut. Not a Tier 2 canonical elaboration.

**Date:** 2026-08-12. **Revision 2**, same day — revision 1 was refuted; see §8.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Status:** One buildable measurement (§3), four pre-declarations pending preconditions (§5), and a record of a framing that was tested and mostly failed (§8). **No new receipt families proposed** (§7).

Composes with: `OBSERVATION-PLANE-2026-07.md`, `BLAST-RADIUS-AND-RECOVERY-2026-07.md`, `TRIAGE-FOR-COHERENCE-2026-07.md`, `REGENT-ADAPTER-WORKFLOW-2026-07.md`, `CHANNEL-BOUNDARY-2026-08.md`, `SUBSTRATE-COORDINATION-DISCIPLINE-2026-07.md`, `REPRESENTATION-LEVEL-TRAINING-2026-08.md`.

---

## 1. What this is, and what it is not

A **buffer** is a reserve of capacity that absorbs stress without producing an event. Depletion is eventless by definition — that is what absorbing means — so a receipt chain that records what happened is structurally blind to it. The failure is nonlinear: the increment that finally fires is identical to the thousand absorbed before it, which means the triggering receipt names the trigger and not the cause.

**This document is prospective, not retrospective.** It does not claim the substrate's failure history demonstrates a buffer problem. It does not — see §8, where that claim was made and refuted at a measured base rate of roughly 2%.

The claim is narrower and testable in the other direction: **a reserve that has not yet begun draining cannot be reconstructed from a chain that was not recording it.** A four-month-old system in active construction has had no time to deplete a multi-year reserve. If the gauge is installed after the history exists, the earliest history is lost. So the correct posture at this stage is to declare the measure now and start it at zero, not to detect drain that has not happened.

That framing carries an obligation the prior revision did not meet. If the entire value is installing the gauge before the drain begins, **the gauge has to exist.** A pre-declaration without a computable `reserve_measure` is a prediction with no instrument. Every entry below either supplies one or is explicitly not a buffer.

## 2. Prior art — this is error budgeting, and the mature version is better

The prior revision re-derived a developed field badly. Recording the field so nobody re-derives it again:

- **Woods, *Theory of Graceful Extensibility* (2018)** — finite adaptive capacity, reserve capacity, saturation, brittleness as sudden collapse at the boundary. This is §1's thesis, stated more rigorously, eight years earlier.
- **Rasmussen's drift-to-danger; Dekker, *Drift into Failure*** — safety margin eroding invisibly under production pressure until the boundary. The erosion argument.
- **Bainbridge, *Ironies of Automation* (1983)** — automation degrades the operator skill it eventually depends on. The unexercised-judgment argument, forty-three years old.
- **SRE error budgeting** — a declared reserve, a burn rate, multiwindow burn-rate alerting, exhaustion projection, and a policy response on exhaustion. This is the prior revision's proposed schema, already shipped, with the window-scaling problem it got wrong already solved.
- **Leading vs. lagging indicators** (safety science) — the event/margin distinction.

**The substrate should adopt error budgeting's shape rather than invent a parallel one.** Where this document adds anything, it is in one place only: §3's observation that forward-only recovery makes recomputation time a first-class safety property, which is specific to this architecture because most systems can roll back and therefore do not have this dependency.

## 3. The one active reserve: recovery margin

**Reserve.** The gap between how long it takes to recompute derived state from the last known-good checkpoint to chain head, and the operationally tolerable recovery window.

**Why this substrate and not others.** Forward-only recovery is doctrine here — chain is truth, roll forward, never back. That makes recomputation *the* recovery path rather than a fallback. Recomputation time is therefore not a performance concern; it is the recovery guarantee. Systems that can roll back do not have this dependency, which is why the general literature covers RTO drift but not this specific coupling.

**`reserve_measure`** — `tolerable_recovery_window − measured_recompute_time`, where `measured_recompute_time` is obtained by drill: select a chain-anchored checkpoint, recompute derived state to head, record wall-clock.

**`drain_measure`** — change in `measured_recompute_time` per 30 days, from repeated drills.

**Operational proxy, computable today with no drill:** `chain_head − last_processed_sequence`. At last measurement the Cartographer cursor was **70,445 entries behind and five days cold**, against a chain of ~285,000 entries. The proxy is not the reserve — a cold cursor is a stopped process, not a slow one — but it bounds it from below and costs one query.

**`exhaustion_condition`** — `measured_recompute_time > tolerable_recovery_window`. Mechanically determined, not a judgment call: past that point forward-only recovery is available in principle and unreachable in practice.

**`nonlinearity`** — discovered during an emergency, because that is the only occasion that exercises it.

**`replenishment_class`** — mechanical (checkpoint more often; improve recompute throughput). But note §6's warning: the obvious autonomic remedy in a forward-only substrate is to shed derived state, which increases recompute distance. Mechanical remediation here displaces stress rather than removing it, and should be operator-dispositioned despite the class.

**Cost to establish the first datapoint: one afternoon, no code.** Pick a checkpoint, recompute, time it, compare. Repeat in ninety days for the second point.

**This is also the disconfirming experiment.** If recompute time sits comfortably inside the window and is growing slower than tolerance, this document's only active claim is refuted on its own terms — cheaply, and with a number.

## 4. Demotions — what was cut and why

Recorded rather than deleted, because the cuts are the useful part.

| Prior entry | Disposition | Reason |
|---|---|---|
| Operator attention | **Cut — not instrumentable** | Exhaustion condition is a judgment, not a mechanical state (§6). The observable it proposed — declining escalation rate — is identical to a healthier substrate with a more rested operator, and no discriminator was supplied. Also a human-mind property, which §III.24 commits the substrate to not observing. |
| Unexercised judgment | **Cut — conflicts with §III.25** | Declining escalation rate is the substrate's *declared success signal* for maturity. Same number, opposite verdicts, no discriminator. Prior art: Bainbridge 1983. This is an operator-practice concern — periodic deliberate exercise of judgment — not a substrate measurement. |
| Aggregate delegation scope | **Cut — already evented** | Every grant is a signed receipt with declared scope. The union is exactly computable from the chain today. Not a buffer; a query nobody wrote. Belongs to Claim 4's adversarial-testing gap. |
| Corpus coherence | **Cut — already instrumented** | `TRIAGE-FOR-COHERENCE-2026-07` measures coverage (331/987 = 33.5%), observed it *fall* across five same-day documents, and independently derived §6's anti-targeting rule a year earlier: *"maturity must never become a target."* Nothing to add. |
| Quorum / key margin | **Cut as a buffer; kept as ops** | It is a threshold by §1's own definition — losses are discrete and aperiodic, so drain rate over any window is identically zero, and recovery is binary rather than graded. Also unobservable without a new attestation surface. **The action is still right:** attest recovery-share count on a schedule and drill recovery. That is standard key-ceremony practice and needs none of this document. |
| Verification vs. chain growth | **Merged into §3** | This was the real entry. Recovery margin is its architecture-specific residue. |
| Adapter capability retention | **Moved to pre-declaration (§5)** | Real and measured in the literature (58.6% → 30%), but the eventlessness is an artifact of not running the prior task's eval. Standard continual-learning practice (backward-transfer matrices) makes it a measured quantity. Preconditions do not exist — no adapters in rotation. |
| Host headroom | **Cut — conventional monitoring** | The only unambiguous buffer in the prior list, and the one needing nothing from this framing. Zero incidents in four months of records. Ordinary host monitoring, not a substrate primitive. |

**One principle earned from the cuts.** Two entries were resolved by *designing the buffer out* rather than measuring it: DECIDED-005 installed a pre-commit hook rather than a commit-backlog gauge, reasoning that *"a pre-commit hook that runs the full workspace test suite will be disabled within a week for being slow… a disabled hook is worse than none"* — and the Sentinel alarm flood was fixed by edge-triggering the classifier, not by measuring finding volume. **Design the buffer out before instrumenting it.** A reserve that cannot be depleted needs no gauge.

## 5. Pre-declarations — measures specified, preconditions unmet

These are not claims that anything is draining. Each names a reserve, its measure, and **the precondition that would make measurement meaningful**. None is built now. The point of declaring them is that when the precondition occurs, measurement starts at zero rather than being reconstructed.

Each must carry a computable measure or it does not belong here.

**5.1 Adapter capability retention**
- `reserve_measure`: accuracy on task *n* after adapting for task *n+k*, against the frozen baseline recorded at task *n*'s promotion. A backward-transfer matrix.
- `drain_measure`: retention delta per adaptation cycle.
- `precondition`: two or more adapters in rotation on the Regent-role node.
- Note: the remedy is already doctrine — **rebuild, don't stack**, per `REPRESENTATION-LEVEL-TRAINING-2026-08.md`. If rebuild-from-corpus is honored, this reserve cannot deplete and the pre-declaration expires unused. That is the preferred outcome.

**5.2 Delegation union scope**
- `reserve_measure`: cardinality and resource-span of the union of active grants, against the declared blast-radius envelope.
- `drain_measure`: union growth per 30 days, net of expiry.
- `precondition`: sustained multi-agent operation with grants outliving a single session.

**5.3 Recovery-share count**
- `reserve_measure`: attested shares held, minus M.
- `drain_measure`: not applicable — this is a threshold, retained here only so the attestation schedule has a home.
- `precondition`: quorum sovereignty actually provisioned. None registered today.

**5.4 Receipt-family liveness**
- `reserve_measure`: declared families with an emitting producer, over families declared. Currently **23 of 674 (3.4%)**; receipt types **3 live of 40**; chain entries carrying a receipt **0 of 285,071**.
- `drain_measure`: change in that ratio per 30 days.
- `precondition`: none — this is computable today, and it is falling.

5.4 is the one pre-declaration that is already active, and it is aimed squarely at this document (see §7).

## 6. The Goodhart constraint, corrected

The prior revision banned composite health scores at the top level while mandating a scalar proxy at every leaf. That was incoherent. The corrected rule:

**A leaf measure is legitimate only when the exhaustion condition is mechanically determined.** Recompute time exceeding the tolerable window means recovery fails — definitionally, not by judgment. Share count below M means recovery is impossible. These admit a measure because crossing them is a fact.

**A reserve whose exhaustion is a judgment gets no gauge.** "The operator is too depleted" has no mechanical threshold, and any number standing in for it becomes the target immediately. This is why §3.1 and §3.4 were cut in §4 rather than merely deferred — not because they are unimportant, but because instrumenting them is the failure mode wearing the fix's clothing. The only way a substrate improves an operator-attention metric autonomically is to tell the operator less.

**No composite.** Reserves report individually with drain direction, or not at all.

**Interdependence holds.** Mechanical remediation can displace stress into another reserve — §3's own case, where shedding derived state to free disk increases recompute distance. Any autonomic remedy must name what it displaces into.

## 7. No new receipt families

The prior revision proposed five. Against the current corpus that is indefensible: **674 receipt families declared in governed prose, 23 emitted; 40 receipt types declared, 3 live, 26 inert; 0 of 285,071 chain entries carry a receipt at all.** `QUESTION-001` — *what makes a receipt family real?* — is open and unowned.

Therefore: **gauges report on the existing health surface as arithmetic over existing state.** No declaration schema, no receipt family, no officer, no ontology object. If a gauge ever warrants chain anchoring, it enters as `reserved` per `CHANNEL-BOUNDARY-2026-08.md` with a `because` and a `review_after`, after `QUESTION-001` is resolved — not before.

A document proposing new receipt families into a corpus with a 3.4% emission rate would be adding to the dominant documented failure class (producer/consumer disjunction, 35% of incidents) in the name of fixing a class that accounts for 2%.

## 8. What this replaces, and what the refutation found

Revision 1 claimed the substrate had a structural blind spot and enumerated eight buffers. It was perturbation-tested the same day by an adversarial refuter and an empirical base-rate check. Recorded because the refutation is more informative than the proposal was.

**Structural findings (these stand regardless of system maturity):**

- §3 supplied `reserve_measure` **0 of 8** and `drain_measure` **0 of 8** — the two fields that make a buffer claim falsifiable. What remained was a template that fits any quantity whatsoever, which is why the enumeration read as strong: nothing in it could fail.
- The staged heuristic was N=0, not N=1 — it cited the thesis as evidence for the thesis.
- The proposal's own cost was a draw on the reserve it claimed to protect. Self-cancelling exactly when it fires.
- Prior art existed for all eight entries, uncited. See §2.

**Empirical finding, and its limit:** 48 documented failures, 2026-05 → 2026-08. One genuine buffer depletion, three under the most generous reading — 2% to 6%. Dominant classes: config/wiring defects 42%, producer/consumer disjunction 35%, misdiagnosis 13%. Six of the eight buffers had zero documented instances.

**That number measures the wrong population, and the limit must be recorded with it.** Buffer depletion is an operation-phase failure mode; the 48 incidents are construction-phase failures of a four-month-old system with no adopters, no sustained autonomous operation, no adapters in rotation, and no quorum provisioned. Six of eight had zero instances substantially because **the preconditions for those reserves to exist have not occurred**. That is absence of experimental conditions, not evidence of absence. The 0-of-285,071 receipt figure cuts the same way: it constrains what the chain could have shown, not what happened.

The base rate therefore refutes revision 1's *retrospective* claim and does not refute the buffer class. Hence this revision's prospective framing, and hence §5.

**One correction to the corpus fell out of this sideways.** `CLAUDE.md`'s entry describing the 2026-08-06 Sentinel flood as drowning the Regent's cognitive context in false-positive noise does not match the chain for that instance: SEAM-009 establishes `send_findings` has a single call site in the wrong task, so the findings never reached the Regent's context. The flood was real (60/hour, constant rate from the defect's ship date — a flat drain curve, which is why it is not a buffer); the stated consequence was not. Worth amending independently of anything here.

## 9. Staged heuristic

**[STAGED — 2 instances, not canonical]** *Design the buffer out before instrumenting it.*

- Instance 1 — DECIDED-005: pre-commit hook rather than a commit-backlog gauge, with the reasoning recorded (a slow hook gets disabled; a disabled hook is worse than none).
- Instance 2 — 2026-08-06 Sentinel flood: fixed by edge-triggering the classifier against a `(pid, process_name)` set, not by measuring finding volume.

Both cases had an available measurement and chose elimination. A third instance would justify canonization.

The prior revision's heuristic — *a system that records only events cannot see itself running out of room* — is **withdrawn**. It was N=0 and it is Woods (2018) restated.

## 10. What composes from here

**Do now:**
1. Run the recovery drill. Checkpoint → head, wall-clock, compare to tolerable window. One afternoon. This either establishes the document's only active claim or refutes it.
2. Query the Cartographer cursor lag as a standing health-surface line. One query.

**Do not do yet:**
3. Nothing in §5. Those wait on preconditions. Revisit 5.1 when a second adapter enters rotation; 5.3 when quorum is provisioned.

**Argue with:**
4. §6's mechanical/judgment split is the load-bearing rule. If it is wrong, §4's two largest cuts were wrong, and the operator-attention question returns — in which case it returns as an operator-practice discipline, not as substrate instrumentation.
5. §5.4 is aimed at this document's own class. If receipt-family liveness keeps falling, the corpus is generating declarations faster than producers, and the correct response to *any* new proposal — including this one — is to decline it until the ratio recovers.
