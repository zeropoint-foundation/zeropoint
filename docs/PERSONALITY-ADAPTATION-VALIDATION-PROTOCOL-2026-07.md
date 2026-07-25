# Personality-Adaptation Validation Protocol — July 2026

**Document type:** Track 1 research deliverable. Expands and supersedes the personality claims in `ARCHITECTURE-2026-07.md` §16. Pre-registration-grade: the metrics, thresholds, and decision rules in this document are committed **before** any outcome data is examined. A threshold set after looking at data is not a threshold.

**Status:** Draft protocol. Not active until the fields marked `[COMMIT BEFORE DATA]` are filled and the document is signed onto the chain. That signing ceremony is the pre-registration.

**Author:** Ken Romero, with synthesis assistance from Claude.

---

## 0. What this document is, and what it refuses to do

The prior architecture (§16) listed Enneagram-adaptive personality intelligence as a private premium differentiator — "the Two is the floor; adaptive attunement is the ceiling," calibrated "with real usage data." That framing asserted the ceiling exists and treated tuning as validation. Tuning is not validation. Tuning assumes the thing works and asks how well; validation asks *whether*.

This document retires the differentiator framing until the capability earns it. The personality-adaptation layer is a **hypothesis under test**, not an asset on the balance sheet. It ships nothing to a customer as a paid capability until it clears the bars defined here. A null result is an accepted, planned-for outcome that closes the line and reverts the system to its default personality — and the architecture is fine if that happens, because the default was always independently good.

The protocol is designed so that no single outcome can be explained away after the fact. Every gate has a pre-committed number. Every arm that could win is allowed to win, including the ones whose winning would kill the feature.

---

## 1. The two bets, kept separate

The adaptive-personality feature stacks two independent empirical claims. The prior framing fused them; this protocol pulls them apart, because they can fail independently and a fused test cannot tell you which failed.

- **Bet A — the typology carries signal.** Adapting the system's personality to an operator's type improves operator-measurable outcomes over not doing so.
- **Bet B — the typer works.** An operator's type can be inferred, reliably and stably, from passive interaction signals rather than questionnaires.

Bet B is the shakier of the two and is tested first, as a precondition. If the typer is noise, every downstream comparison that depends on "the operator's correct type" is meaningless, because "correct" has no referent.

---

## 2. The ladder

Four questions, tested in fixed sequence. Each gate must pass on its pre-committed rule before the next runs. **Stop at the first gate that returns null.** Stopping early is not failure of the study; it is the study working, and it is what keeps the family-wide false-positive rate controlled without penalty (fixed-sequence gatekeeping).

| Rung | Question | Primary comparison | Gate to proceed |
|------|----------|--------------------|-----------------|
| **Q0** | Is the inferred type *stable* at all? (Bet B) | Test–retest agreement of the typer across independent sessions for the same operator | `[COMMIT BEFORE DATA]` reliability floor |
| **Q1** | Does personality-shaping matter *at all*? | Neutral assistant (N) vs. any fixed archetype (R) | R beats N by ≥ `[COMMIT]` on primary metric |
| **Q2** | Does the *right* type matter, or just *a* type? (the Forer-killer) | Fixed inferred-correct type (I) vs. fixed random type (R′) | I beats R′ by ≥ `[COMMIT]` |
| **Q3** | Does dynamic *adaptation* beat static typing? | Adaptive (A) vs. fixed inferred (I) | A beats I by ≥ `[COMMIT]` |

Q2 is the load-bearing rung. It is the specific guard against a Forer outcome — the risk that any plausibly-worded type description feels apt, so adapting to the "right" type and a random-but-consistent type land identically. If I ≈ R′, the typology is not doing work even if Q1 passed, because a random label performed as well as the "correct" one. This is the rung most likely to kill the feature, which is exactly why it exists.

---

## 3. The arms

| Arm | Description | Role |
|-----|-------------|------|
| **N** | Neutral assistant — competent, helpful, no archetype, no adaptation | True control for Q1 |
| **R** | Fixed *random* archetype, held constant per operator, theory-agnostic pick | "Does *a* consistent personality help" |
| **R′** | Fixed random *type* from the typology, held constant, ≠ operator's inferred type | Forer control for Q2 |
| **I** | Fixed inferred-correct type, held constant (no stress/growth movement) | Static-typing treatment |
| **A** | Full adaptive layer — inferred type plus dynamic stress/growth movement | The feature as pitched |
| **T** | Fixed healthy Two (the public default) | **Benchmark arm — allowed to win** |

**On the Two (T).** The Two is *not* the control. It is the framework's own pick for the strongest general-purpose archetype, which makes it a treatment, not a neutral baseline — racing adaptation against the framework's champion would confound a null. So it is ejected as the control. But it is retained as a **benchmark arm that is permitted to beat everything**. If T beats A, that is not contamination to be explained away — it is a finding: *ship the fixed Two, skip the typing apparatus entirely.* That outcome is decision-relevant and must be reportable, not defined out of existence. Any analysis that treats "the Two won" as a broken experiment is rejected.

---

## 4. Primary metric and the construct-validity trap

**Primary metric:** `[COMMIT BEFORE DATA — choose exactly one]`. Candidate, chain-measurable, from §9 inference receipts and existing chain state:

- Clarification rounds per completed task (proxy for friction / attunement)
- Delegation-scope corrections per session (operator overriding the Regent's proposed scope)
- Override / rejection frequency at the gate
- Task-completion rate on held-out tasks

**Secondary metrics:** the remaining candidates above, reported but not gating.

**Independent outcome family — blind operator rating.** "Feels attuned" is the actual pitch, so measure it directly rather than dodge it. A periodic, arm-blind operator rating ("how well did the system understand what you needed?"). This is a *separate* family from the behavioral metrics and is not a substitute for them.

**The trap this guards against.** A single behavioral proxy is gameable in a way that inverts its meaning. A sycophantic or over-agreeable personality could *reduce* clarification rounds while being *worse* — it stops asking and just guesses. So the behavioral metric and the blind satisfaction rating must move together for a "win" to count. A pre-committed rule: an arm wins a rung only if it improves the primary behavioral metric by ≥ threshold **and** does not degrade blind satisfaction beyond `[COMMIT]`. Improving one by harming the other is not a win; it is a warning.

---

## 5. Design controls (the things that keep a "win" honest)

- **Within-operator randomization.** Arm assignment randomized at the session or task level for the *same* operator, so operator-identity is not confounded with arm. Person-type and config-type must vary independently.
- **Effort parity.** Model tier, inference budget, and token spend held equal across arms — enforced through §11 cost governance, which already meters per-task tokens. Otherwise you confirm the hypothesis by handing the treatment more compute. Any arm that spends more per task than another by > `[COMMIT]`% invalidates that comparison.
- **Blinding.** Operator blind to the live arm wherever the interaction makes that feasible. Analyst blind to arm labels until the primary analysis is locked.
- **Held-out sessions.** Gate decisions computed only on sessions not used for any typer calibration or prompt tuning. Tuning data and evaluation data do not overlap. Ever.
- **Pre-committed analysis method.** Mixed-effects model with operator as a random effect; primary comparison per rung specified in advance. `[COMMIT: model form]`.
- **Power before running.** A pilot estimates outcome variance and the minimum detectable effect. A power analysis sets required N per arm *before* the confirmatory run begins. Inputs required to finalize this section: pilot variance estimate, target power (≥ 0.8), and the smallest effect worth shipping for. Underpowered arms are not run.

---

## 6. Decision rules (committed before data)

For each rung, exactly one of three outcomes, all pre-defined:

1. **Pass** — treatment beats its control by ≥ the committed threshold on the primary metric, without degrading the blind-satisfaction family. Proceed to next rung.
2. **Null** — threshold not met. **Stop the ladder.** Do not run lower rungs. Record the null on the chain. The feature reverts to the last passing configuration (or to Neutral / the Two if Q1 itself is null).
3. **Inconclusive** — underpowered or metric families disagree. Do not proceed; either collect more data to the pre-set N or stop. Inconclusive is *not* re-run-until-significant; the stopping N is fixed in advance.

**What each terminal null means, stated now so it cannot be re-narrated later:**

- **Q0 null** — the typer is noise. Bets downstream are unrunnable. The feature does not ship in any typed form. This is the cheapest and most likely place to stop.
- **Q1 null** — personality-shaping does nothing measurable over neutral. The entire personality edifice — including the Two — is decorative with respect to outcomes. Ship neutral; close the line.
- **Q2 null** — a random type performs as well as the correct one. The typology carries no operator-specific signal (Forer outcome). Ship a fixed personality (whichever benchmark won); discard the typing apparatus.
- **Q3 null** — static typing is as good as dynamic adaptation. Ship fixed inferred type; discard the stress/growth movement machinery.
- **T beats the winning treatment at any rung** — ship the fixed Two; the adaptive apparatus is not worth its complexity. A finding, not a failure.

---

## 7. The symmetric commitment

The discipline cuts both ways or it is not discipline.

This protocol is built to let the feature fail, because the prior framing was built to let it succeed by assertion. But "test it first" must not quietly become "shelve it forever." If a rung **passes** on its pre-committed rule, that is genuine evidence and is treated with the same seriousness as a null: the line advances, the next rung runs, and the commercialization language struck from §16 begins to be earned back — now attached to a number instead of a claim. The committed position is not *the typology is empty* and never was. It is *the typology is an untested hypothesis and is treated as exactly that, until the chain says otherwise, in whichever direction it says it.*

The bet, stated honestly: whoever set the thresholds will believe the result whichever way it points. That is the only thing that makes this pre-registration rather than a worldview collecting confirmations.

---

## 8. Instrumentation notes (what already exists)

Most of the harness is already built, which is fitting given the thesis is that governed systems produce verifiable records.

- §9 already receipts model, prompt, response (or hash), and resulting action per inference. That is the raw event log for every behavioral metric.
- §11 already meters per-task and per-session token/compute cost. That is the effort-parity enforcement surface.
- The chain is the experiment log: arm assignment, per-session outcomes, and gate decisions are themselves receipts, hash-linked and replayable. The analysis is re-derivable from the chain, which means the result is auditable the same way every other claim in the system is.

What must be added: the arm-assignment randomizer (chain-anchored, so assignment is verifiable and not retroactively editable), the typer's test-retest harness for Q0, and the blind operator-rating prompt.

**Recruitment mechanism.** How the Foundation reaches potential participants without violating the sovereignty properties this protocol depends on is specified in `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md`. In summary: the Foundation emits a chain-signed announce under the `foundation:research:invitation` category carrying the mandate template hash for this study. Operators whose local subscription filters accept research invitations receive the announce and can — if they choose — issue a capability-grant mandate authorizing the pre-registered queries in §8 above. The Foundation never holds a subscriber list, never learns the identity of any non-participating operator, and can only query the chains of operators who have explicitly opted in. Withdrawal is mandate revocation — a single receipt, effective immediately.

---

## 9. Open fields to close before signing

- [ ] Primary metric selected (§4)
- [ ] Reliability floor for Q0 (§2)
- [ ] Effect thresholds for Q1, Q2, Q3 (§2)
- [ ] Satisfaction-degradation ceiling (§4)
- [ ] Effort-parity tolerance (§5)
- [ ] Analysis model form (§5)
- [ ] Pilot variance estimate + power analysis → N per arm (§5)
- [ ] Stopping N for "inconclusive" (§6)

When these are filled and the document is signed onto the chain, the pre-registration is complete and the confirmatory run may begin. Not before.

---

## 10. Companion Documents

- `docs/ARCHITECTURE-2026-07.md` — canonical architecture; §16 personality claims that this protocol supersedes; §9 inference receipts and §11 spending governance that provide the instrumentation surface.
- `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md` — recruitment mechanism via `foundation:research:invitation` announces; the sovereign-aligned participation model this protocol depends on.
- `docs/design/REGENT-GOSSIP-VALIDATION-2026-07.md` — sibling investigation inheriting the pre-registration discipline defined here.
- `docs/design/REGENT-SECURITY-CHANNEL-INVESTIGATION-2026-07.md` — sibling investigation inheriting the pre-registration discipline defined here.
- `docs/design/TESTBED-AND-PHASING-2026-07.md` — the operational plan for the testbed investigations; this protocol runs separately on real recruited operators outside the testbed, coordinated as its own track.
- `docs/COGNITIVE-DESIGN-PRINCIPLES-2026-07.md` — the multi-timescale user model and three context flows underlying the typology this protocol tests.
