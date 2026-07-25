# Security Signal Channel — July 2026

**Document type:** Design note. Specifies the time-critical security signal channel — how operators coordinate threat detection, alert propagation, and mitigation response through their Regents. Separate from the gossip system (`regent-gossip-and-evolution-2026-07.md`), which handles substrate self-improvement. Both mechanisms coexist because their content types have fundamentally different properties.

**Status:** Design draft.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-05.

---

## Part I — What This Is

Time-critical security coordination between operators. When an active attack, credible threat, or observed compromise needs to reach other operators before it can hurt them.

Distinct from gossip because security signal has properties gossip explicitly rejects: urgent (missed alerts hurt), not locally verifiable (you can't re-run "I'm being attacked" on your own hardware), requires source trust (verification-as-trust-model doesn't work), high cost of false negatives. Forcing security into gossip would break gossip's clean properties; running gossip with security semantics would break gossip's threat model.

The channel lives under the `security:*` namespace for operator-issued signals and extends the `foundation:security:advisory` model from `COMMUNITY-COORDINATION-ON-ZEROPOINT-2026-07.md` for Foundation-issued advisories. The `security:*` namespace is distinct from the anonymous `commons:*` namespace (locally-verifiable patterns) — security signals need identified sources because the claims aren't locally verifiable, per the July 2026 corpus audit resolution of Decision E. Earlier drafts of this doc referenced `commons:security:*` categories that were never actually specified in `PEER-DISCOVERY-AS-OUTREACH-2026-07.md`; that namespace is retired in favor of the cleaner separation between anonymous emissions (commons) and identified emissions with composite trust (security).

---

## Part II — Three Tiers

Signal urgency is explicit in the category:

- **`security:advisory`** — informational. "Watch for this." No immediate action expected.
- **`security:alert`** — respond when able. "This attack is active in the wild." Operator should review, apply mitigation if applicable, but not drop other work.
- **`security:urgent`** — respond now. "Imminent, targeted, or catastrophic." The Regent surfaces immediately regardless of DND, current context, or attention filters.

Foundation-issued advisories use the `foundation:security:*` prefix (per PEER-DISCOVERY §11); operator-issued signals use `security:*` directly.

The tier is declared by the sender. It's a claim, not an authorization. False urgent-tier claims are a HarmPrincipleRule violation because engineered panic causes harm — and Aegis specifically watches for that pattern.

---

## Part III — Signal Types

Five signal types. `threat_observed` describes an attack pattern with indicators, context, and evidence. `ioc_share` carries structured indicator artifacts — hashes, network signatures, behavior patterns. `mitigation_recommendation` offers a response for affected operators, with expected effect and side effects. `coordination_request` asks for specific action from qualifying operators. `incident_update` follows up on prior signals — the threat has evolved, been contained, or turned out to be a false alarm.

Signals are chain-anchored receipts. Each carries a signer, timestamp, tier claim, and type-specific payload.

---

## Part IV — Trust Model

Security signal cannot rely on local verification the way gossip does. You cannot re-run "I'm being attacked" against your own hardware. Trust in security signal is composite:

- **Source reputation** — the sender's chain-anchored history of security signal accuracy.
- **Corroboration weight** — independent sources reporting the same signal, weighted by their independent reputations.
- **Officer attribution** — signals originating from Sentinel or emitting to Aegis carry different weight than raw operator-emitted signals.
- **Recency** — old signals decay in weight; new corroborations refresh them.

The Regent computes trust from these factors and presents evidence to the operator alongside the signal itself. The operator sees "three independent operators with strong security reputation report this pattern; corroborated within the last hour." Not a normalized trust score.

Trust is descriptive, not gating. The operator decides what to do; the Regent presents the evidence.

---

## Part V — Officer Integration

Sentinel is the primary security officer. He produces security signals from his local observation of the operator's substrate and consumes peer signals into his own posture assessment. Aegis observes across the security signal stream itself — adversarial patterns like false injection, urgency inflation, and coordinated poisoning are exactly what he was designed to notice. Aegis findings about the security channel become chain receipts that inform the Regent's trust computation.

Steward observes the security signal chain for integrity. Forge observes operational patterns triggered by security response. Cleo narrates for the operator. The five-officer cadre continues to operate as designed; the security channel is another domain each officer touches from their own angle.

---

## Part VI — Mitigation Adoption

Alerts often carry mitigation recommendations. Before an operator adopts one, the Regent A/B tests it against the operator's specific context — same adoption architecture as everything else in the substrate. Present the evidence, operator decides.

For urgent signals where the window is too tight for full A/B testing, the Regent presents the mitigation with a clear "not locally validated" note. The operator can proceed anyway (accepting the risk explicitly) or defer. Compressed-window mitigation adoption is a documented degradation of the validation gate, not a bypass of it.

---

## Part VII — Priority Handling

Priority handling breaks the Regent's normal noise-filtering rules. Urgent signals surface immediately regardless of operator DND, active session, or attention filters. Alert signals get queued but marked time-sensitive. Advisory signals flow through normal filtering.

This creates an attack surface: engineered urgency to force operator attention. Aegis specifically watches for this pattern — repeated urgent-tier claims from a source whose signals don't post-hoc justify the claim degrade that source's future priority handling. A source that falsely cries wolf loses the ability to make the operator's phone ring.

---

## Part VIII — Adversarial Considerations

Three main attack patterns:

- **False injection.** Adversary broadcasts fabricated threat. Defense: source reputation attribution + corroboration requirement + Aegis pattern detection. Same defenses as any other adversarial signal, but reputation carries more weight here because local verification isn't available.
- **Urgency inflation.** Adversary claims urgent tier for signals that don't warrant it. Defense: post-hoc validation of urgent claims + Aegis-driven degradation of future priority handling from sources with false urgency history + constitutional grounding.
- **Alert fatigue.** Not adversarial exactly — but too many low-value alerts train operators to ignore signals. Defense: the tier system itself + reputation-weighted filtering + operator-tunable thresholds + Regent-mediated presentation that groups related signals.

Sophisticated coordinated attacks combining these patterns are what the investigation companion note (`REGENT-SECURITY-CHANNEL-INVESTIGATION-2026-07.md`) is designed to pressure-test.

---

## Part IX — Composition

- `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md` — `foundation:security:*` announce categories for Foundation-issued advisories; `security:*` namespace for operator-issued signals extends the same transport model.
- `docs/design/COMMUNITY-COORDINATION-ON-ZEROPOINT-2026-07.md` — the `foundation:security:advisory` model this extends.
- `docs/design/TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md` — Aegis's role in adversarial-pattern detection.
- `docs/design/DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md` — reputation and corroboration dynamics.
- `docs/design/regent-gossip-and-evolution-2026-07.md` — the gossip system this channel is intentionally separate from.
- `docs/design/REGENT-SECURITY-CHANNEL-INVESTIGATION-2026-07.md` — the empirical investigation of this design.
