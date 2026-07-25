# Regent Security Channel Investigation — July 2026

**Document type:** Investigation plan. Empirically validates the security signal channel design in `SECURITY-SIGNAL-CHANNEL-2026-07.md` — does the composite trust model hold under adversarial pressure, does the tier system prevent alert fatigue, does officer integration produce coherent behavior? The gossip system has its own separate validation questions; this one focuses on the security channel.

**Status:** Pre-registration draft. Metrics, thresholds, and success criteria committed before scenarios execute.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-05.

---

## Part I — The Approach

Take the security signal channel design and run it against real substrate mechanisms with hybrid scenarios. Real attack patterns as inspiration, synthetic execution against simulated operators. Substrate mechanisms are real (receipts and hash-linked chain, reputation dynamics, mandate scopes, constitutional rules, officer cadre with Aegis, Cartographer trajectory attribution). Threat content is fabricated to keep the investigation contained.

---

## Part II — Five Questions

Committed before execution:

1. **Trust model convergence.** Does the composite trust (source reputation + corroboration + officer attribution + recency) converge to reliable signal, or does it produce noise the operator can't act on?
2. **Tier discipline.** Does the three-tier system prevent alert fatigue, or do sources drift toward inflated urgency over time?
3. **Adversarial defense.** When bad actors inject false threats or inflate urgency, do reputation dynamics, Aegis pattern detection, and constitutional grounding catch them? At what timescale?
4. **Officer integration coherence.** Do Sentinel-produced signals, Aegis observations of the security stream, and other officer contributions compose into coherent posture, or do they conflict?
5. **Compressed-window mitigation adoption.** Does the Regent A/B gate hold when the window for testing a mitigation is compressed by urgency, or does time pressure degrade its validity?

---

## Part III — Scenarios

Six scenarios. The baseline runs each operator independently with no security channel to give a reference measure of threat detection speed. Cooperative sharing runs the channel as designed. Adversarial injection introduces one or two bad-faith operators to test whether the trust model catches them. Tier gaming has adversaries claim urgent tier for low-value signals to see whether Aegis and reputation dynamics degrade their future priority handling. Alert fatigue floods the channel with legitimate but low-relevance advisories to see whether operators tune out real alerts. Compressed-window adoption runs scenarios where the mitigation A/B window is deliberately compressed by urgency to test whether the adoption architecture holds when speed matters.

---

## Part IV — Adversarial Variants

Seven attack patterns. Fake threat injection tests basic false-signal defense. Urgency inflation tests whether fake urgent claims degrade the sender's future priority handling. Reputation laundering has adversaries share accurate advisories for months to build reputation before defecting with a poisoned urgent alert. Corroboration collusion coordinates multiple adversarial identities to falsely corroborate a fabricated signal. Response poisoning shares mitigations that appear helpful but weaken the substrate over time — testing whether the A/B gate catches subtle harm. Engineered panic uses urgent-tier signals to force operators into actions they wouldn't take under calm evaluation. Legitimate-looking evasion crafts threats indistinguishable from real signal until harm manifests — included specifically as a case we expect to slip through initial detection and catch only retroactively. Learning where the substrate's limits are matters as much as learning what works.

---

## Part V — What Emerges

Four outcomes, committed before findings:

- **It works.** Trust model converges to usable signal; tier discipline holds; adversarial defense catches injections at usable timescale. Next: implement the channel per the design.
- **Missing primitives revealed.** Some mechanism proves insufficient — say, corroboration weighting doesn't work without persistent cross-context reputation. Next: name what's missing and propose as ZEPs. Don't silently retrofit.
- **Inconclusive.** Scenarios too artificial, effects too subtle. Next: refine methodology or defer implementation pending better grounding. Do not conclude the design is sufficient just because we couldn't measure otherwise.
- **It doesn't work.** Coordinated attack degrades outcomes vs. baseline; alert fatigue leaves operators worse off than isolated operation. Next: honestly report; reconsider whether a coordinated security channel is the right shape or whether operators are better off with isolated defense.

Each outcome gets equal weight. The investigation informs, not confirms.

---

## Part VI — Real vs. Simulated

**Real:** substrate mechanisms — receipts and chain, reputation dynamics, mandate scopes, constitutional rules, officer cadre with Aegis, Cartographer trajectory attribution, Regent compartmentalization, the security signal channel implementation.

**Simulated:** operators (personas, not real people), Regent inference (specific model class documented per scenario), threat content (fabricated IOCs), mesh transport (in-process for this stage), time.

Patterns emerging in real mechanisms are strong signal. Patterns emerging in simulated components are indicative — dependent on the inference substrate used.

---

## Part VII — Pre-registration

Metrics, thresholds, personas, scenario schedule, and analysis code committed on the investigation's chain before scenarios begin. Post-hoc modification is chain-visible and treated as a research integrity failure. An independent reviewer signs off on methodology before execution.

---

## Part VIII — Companion Documents

- `docs/design/SECURITY-SIGNAL-CHANNEL-2026-07.md` — the design under test.
- `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md` — announce transport.
- `docs/design/TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md` — Aegis's role.
- `docs/design/DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md` — reputation and corroboration dynamics.
- `docs/design/REGENT-COMPARTMENTALIZATION-2026-07.md` — Regent scope mediation.
- `docs/design/SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md` — Regent build integrity.
- `docs/design/COMMUNITY-COORDINATION-ON-ZEROPOINT-2026-07.md` — the `foundation:security:advisory` reference model.
- `docs/design/regent-gossip-and-evolution-2026-07.md` — the parallel mechanism this is intentionally separate from.
- `docs/design/TESTBED-AND-PHASING-2026-07.md` — the operational plan; this investigation's baseline runs in Phase 2 with fuller adversarial scenarios in Phases 4-5.
- `docs/PERSONALITY-ADAPTATION-VALIDATION-PROTOCOL-2026-07.md` — the pre-registration discipline this inherits.
