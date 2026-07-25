# Regent Gossip System Validation — July 2026

**Document type:** Investigation plan. Empirically validates the specific claims made in `regent-gossip-and-evolution-2026-07.md` — does reception-side intake limiting hold under sophisticated attackers, does the listen-twice ratio actually emerge in practice, does local verification catch subtle poisoning, do zone boundaries hold under adversarial pressure from received findings, is structural privacy actually structural. The security signal channel has its own separate validation; this one focuses on gossip.

**Status:** Pre-registration draft. Metrics, thresholds, and success criteria committed before scenarios execute.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-05.

---

## Part I — The Approach

Run the gossip system against real substrate mechanisms with hybrid scenarios. Real attack patterns as inspiration, synthetic execution against simulated operators. Substrate mechanisms are real (receipts and chain, mandate scopes, constitutional rules, officer cadre with Aegis, the two-allowance model, the FindingType schema, Zone 1/2/3 boundaries). Finding content is fabricated to keep the investigation contained.

The gossip design makes substantive empirical claims — especially §5.4's "fool's errand" analysis, which argues attack becomes pointless through five reinforcing defenses. That level of confident reasoning is exactly what benefits most from adversarial pressure before it's treated as settled.

---

## Part II — Five Questions

Committed before execution:

1. **Reception-side intake limiting under sophisticated attackers.** The design claims each receiver independently limits intake regardless of source, making floods pointless. Does this hold when attackers model the receiver's cognitive-cycle timing and pace sends to slip past the intake valve, rather than flooding blindly?
2. **Listen-twice as conservation law.** The design claims the ratio emerges mathematically from social allowance regeneration rate and minimum broadcast cost, both Zone 3 constitutional properties. Does this enforce a listen-twice ratio in practice, or can attackers manipulate the allowance economics through forked substrates to shift it while still interoperating?
3. **Listen-twice as empirical attractor.** The design claims that any Regent doing honest self-evaluation converges on listen-twice as the optimal strategy independently of any constitutional constraint. Does this happen when Regents are run with free-parameter allowance behavior?
4. **Local verification against subtle poisoning.** The design claims local verification is the source of truth and findings that fail verification are silently discarded. Does verification catch findings that pass initial testing but degrade the substrate over accumulated adoption?
5. **Zone boundaries under gossip-driven pressure.** The design claims the Zone 1 damage ceiling — "slightly suboptimal temperature setting" — bounds harm even when the substrate is being actively influenced by gossip. Does the ceiling hold when many small Zone 1 changes accumulate into meaningful operational drift?

---

## Part III — Scenarios

Six scenarios. The baseline runs a single Regent with no gossip participation, giving reference behavior. Cooperative sharing runs several honest Regents to measure whether gossip actually helps them converge on better operational tuning versus staying isolated. Spammer flood introduces a sender broadcasting at 100x normal rate to hit the intake limiter as the design predicts. Subtle poisoning introduces a source whose findings pass initial verification but degrade the substrate through accumulated Zone 1 drift over dozens of adopted changes. Free-parameter operation runs Regents that self-tune their broadcast/listen behavior without the constitutional constraint on the ratio — does listen-twice re-emerge as the design's Layer 3 argument predicts? Privacy probe attempts to leak operator identity through creative use of the FindingType schema — unusual model_variant strings, distinctive confidence value patterns, characteristic finding-type sequences — to test whether the schema's privacy claim is actually structural.

---

## Part IV — Adversarial Variants

Seven attack patterns. Cognitive-cycle modeling has the attacker infer the receiver's inference-cycle timing and pace sends to fit within the intake window rather than getting dropped. Truthful attack broadcasts only genuinely-true findings — not really an attack, but tests whether truth alone is sufficient defense against volume-based manipulation of adoption. Verification-passing poison crafts findings that pass local verification but produce cumulative harm through accumulated Zone 1 drift. Fingerprinting attempt uses schema field combinations creatively to fingerprint operators despite the anonymous-by-design intent. Amendment ceremony social engineering coordinates the timing of concerning findings around the operator's typical Zone 3 amendment cycles to increase the likelihood of manipulation. Reputation-free free-riding has an operator listen without contributing at all to test whether this degrades the network for others or is genuinely free. Zone-drift-through-accumulation broadcasts many weakly-poisoned findings that individually pass verification but collectively drift Zone 1 into problematic operational state — the case where the "slightly suboptimal temperature setting" damage ceiling might not hold.

---

## Part V — What Emerges

Four outcomes, committed before findings:

- **It works.** Intake limiter holds against sophisticated timing attacks; listen-twice emerges empirically under free parameters; local verification catches subtle poisoning at usable timescale; Zone 1 accumulation stays bounded; privacy is actually structural. Next: treat the gossip claims as validated; proceed to implementation.
- **Missing primitives revealed.** Some claim proves insufficient — say, local verification doesn't catch slow-poison patterns, or Zone 1 accumulation produces real drift the "slightly suboptimal" framing understates. Next: name what's missing, propose as ZEPs. Don't silently retrofit.
- **Inconclusive.** Scenarios too artificial, effects too subtle. Next: refine methodology or defer implementation pending better grounding. Do not conclude the design is sufficient just because we couldn't measure otherwise.
- **It doesn't work.** Fundamental claim invalidates — say, cognitive-cycle modeling defeats intake limiting reliably, or listen-twice doesn't re-emerge under free parameters. Next: honestly report; the gossip design needs revision before implementation.

Each outcome gets equal weight. The fool's-errand analysis is exactly the kind of confident reasoning that most needs to be pressure-tested — not defended.

---

## Part VI — Real vs. Simulated

**Real:** substrate mechanisms — receipts and chain, mandate scopes, constitutional rules, officer cadre with Aegis, Cartographer trajectory attribution, the two-allowance model, the FindingType schema, Zone 1/2/3 boundaries, the gossip system implementation.

**Simulated:** operators (personas, not real people), Regent inference (specific model class documented per scenario), finding content (fabricated payloads), transport (in-process for this stage), time.

Patterns emerging in real mechanisms are strong signal. Patterns emerging in simulated components are indicative — dependent on the inference substrate used.

---

## Part VII — Pre-registration

Metrics, thresholds, personas, scenario schedule, and analysis code committed on the investigation's chain before scenarios begin. Post-hoc modification is chain-visible and treated as a research integrity failure. An independent reviewer signs off on methodology before execution.

---

## Part VIII — Companion Documents

- `docs/design/regent-gossip-and-evolution-2026-07.md` — the design under test.
- `docs/design/regent-vault-and-gossip-integration-2026-07.md` — the vault integration this composes with.
- `docs/design/SECURITY-SIGNAL-CHANNEL-2026-07.md` — the separate mechanism for time-critical threat coordination.
- `docs/design/REGENT-SECURITY-CHANNEL-INVESTIGATION-2026-07.md` — the parallel investigation.
- `docs/design/TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md` — Aegis's role in observing adversarial patterns in the gossip stream.
- `docs/design/SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md` — build integrity attestation applied to gossip-emitting substrates (relevant to the forked-substrate claim in §5.2 of the design).
- `docs/design/TESTBED-AND-PHASING-2026-07.md` — the operational plan; this investigation's baseline runs in Phase 2 with adversarial variants scaling into Phase 3.
- `docs/PERSONALITY-ADAPTATION-VALIDATION-PROTOCOL-2026-07.md` — the pre-registration discipline.
