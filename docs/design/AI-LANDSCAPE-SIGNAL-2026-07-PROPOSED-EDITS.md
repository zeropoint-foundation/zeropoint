# Proposed Edits — AI Landscape Signal (2026-07)

Companion to `AI-LANDSCAPE-SIGNAL-2026-07.md`. Five additive edit blocks, one per affected Tier-2 doc. Each is additive (append/insert; no existing prose rewritten) and cites the signal brief so the reasoning trail is walkable.

**Status (2026-07-21):**

| Edit | Target | Status |
|---|---|---|
| E1 | INFERENCE-ROUTING-DISCIPLINE | **APPLIED (2026-07-22)** — data-backed by the APOLLO benchmark; measured note appended to the doc |
| E2 | DEPENDENCY-POSTURE | **APPLIED (2026-07-22)** — data-backed by the APOLLO benchmark; measured note appended (hedge → measured baseline) |
| E3 | SUBSTRATE-HARDENING-CEREMONY | **APPLIED** — additive external-signal note appended |
| E4 | SOVEREIGN-KINSHIP-PRIMITIVES (+ DEPENDENT-SOVEREIGNTY xref) | **APPLIED** — scenario note appended; the `kinship:challenge:*` primitive-vs-composition question remains an open design decision |
| E5 | CRYPTOGRAPHIC-SOVEREIGNTY-AND-LEGAL-PROCESS | **APPLIED** — additive external-signal note appended |

The blocks below are retained as the authored source of the applied notes and the held nominations.

Convention followed: the corpus already carries dated inline motivations ("Amended 2026-07-18 following SLM failure-mode analysis"; "Motivated 2026-07-18 by Nikon…"). These match that pattern with a 2026-07-21 external-signal citation.

---

## E1 — `docs/design/INFERENCE-ROUTING-DISCIPLINE-2026-07.md`

**Where:** end of the `## Framing` section (after the three-properties list), or as a note under `### Routing policy: the precedent bright-line`.

**Insert:**

> **External-signal note (2026-07-21).** The Kimi K3 open-weights release is a market data point on the *local-frontier floor* the substrate has been treating as empirically unknown (KEEL glossary, *inference-sourcing*). Reaching near-frontier capability with an open model now means a large, expensive-to-serve model (~64 accelerator cores cited for top performance; ~$15/M output tokens; lower token-efficiency than frontier proprietary) — a corporate footprint, not a home one. This reinforces the precedent→SLM / novelty→LLM bright-line as the *economic* answer, not only the capability answer: the substrate does not attempt frontier-class general reasoning locally: it runs stable, precedent-shaped work on cheap local SLMs and reserves rally/cloud budget for genuine novelty. The "cheap efficient open model at the frontier" assumption is false; the discipline already assumes it. See `AI-LANDSCAPE-SIGNAL-2026-07.md` §1.

---

## E2 — `docs/DEPENDENCY-POSTURE.md`

**Where:** Tier 3 → "LLM API providers — Cognition layer", appended under the existing **Gap** / **Status** lines.

**Insert:**

> **External-signal note (2026-07-21).** Market commentary around the Kimi K3 release argues the baseline consumer/enterprise posture is now "hold at least one model plus a backup, and assume no single provider is load-bearing." That reframes the local-inference-backend item below from *strategic hedge* to *baseline table stakes*: a substrate whose cognition layer can be disrupted by one provider's pricing, policy, acquisition, or a distribution restriction is structurally fragile in exactly the way the market is now pricing in. Recommend elevating the local-inference-backend priority accordingly, and treating the local/rallied/cloud multi-source axis (SUBSTRATE-FORM inference-sourcing) as the operational expression of *there is no center*. See `AI-LANDSCAPE-SIGNAL-2026-07.md` §2.

**Optional companion:** add a one-line Review-Cadence trigger — "when an external market signal materially changes a dependency's risk framing (e.g., inference-provider disruption becomes baseline expectation)."

---

## E3 — `docs/design/SUBSTRATE-HARDENING-CEREMONY-2026-07.md`

**Where:** near the framing of "hardening is ongoing state maintenance, not one-time badge."

**Insert:**

> **Threat-environment note (2026-07-21).** External signal (Kimi K3 open-weights release; see `AI-LANDSCAPE-SIGNAL-2026-07.md` §3) indicates offensive capability is commoditizing: capable, lower-guardrail open models usable for cloning, exploit assistance, and attack tooling at low cost through H2 2026. This does not change the hardening model — it confirms its premise. Two implications for cadence: (1) the attacker's access to a strong model is now as cheap as the defender's, so the interval between adversarial hardening passes should be treated as a live parameter, not a formality; (2) SECURITY-SIGNAL-CHANNEL timeliness matters more as the population of capable adversaries grows. Consistent with *detectability over invulnerability* — the substrate does not bet on preventing a well-resourced attacker, it bets on making the residual surface visibly measurable.

---

## E4 — `docs/design/SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md`  ⚠ decision, not a paste

**Where:** as a new canonical scenario under the coordination scopes, cross-referenced from `DEPENDENT-SOVEREIGNTY-2026-07.md`.

**The observation:** the "family safe-word against voice/likeness clones" that the outside world reaches for is the low-tech shadow of a Genesis-rooted challenge between kin — a shared secret a clone cannot hold because it lacks the *key*, not because it sounds wrong. The dementia-wire-fraud case ("grandpa, it's me, wire the money") maps onto DEPENDENT-SOVEREIGNTY's already-named elderly-cognitive-decline persona plus kinship safety-check scopes.

**Proposed scenario text (additive):**

> **Verified-kin challenge (anti-impersonation).** A canonical coordination scenario: kin verify a purported contact against likeness/voice impersonation via a Genesis-rooted challenge rather than recognition. The defended case is deepfake-enabled social engineering — a cloned voice or video requesting an urgent, irreversible action (classically, wire fraud targeting a cognitively-vulnerable dependent). The challenge is narrow, mutual, and purposeful: it answers "is this really my kin?" and nothing more. It is **coordination, not oversight** — it must not compose into a kinship-graph, copresence-history, or life-review surface, and it produces no retained record of *who challenged whom* beyond the minimum. Composes with DEPENDENT-SOVEREIGNTY guardian scopes (a guardian may hold challenge capability for a dependent who cannot reliably self-verify).

**Decision flagged (do not paste blindly):** does this warrant a first-class `kinship:challenge:*` primitive, or do the existing `safety_check` + `copresence` scopes + a Genesis-rooted challenge already cover it as a composition? Recommend the latter unless a concrete affordance (offline challenge, dependent-held challenge token, guardian-proxied challenge) needs its own receipt schema. See `AI-LANDSCAPE-SIGNAL-2026-07.md` §4. This is the one signal dimension that may be additive rather than confirmatory — worth a deliberate design pass.

---

## E5 — `docs/design/CRYPTOGRAPHIC-SOVEREIGNTY-AND-LEGAL-PROCESS-2026-07.md`

**Where:** among the edge-cases / foreseeable-stressors framing.

**Insert:**

> **External-signal note (2026-07-21).** Market commentary (see `AI-LANDSCAPE-SIGNAL-2026-07.md` §5) anticipates governments (US and China) restricting model distribution and a fragmenting, multi-provider landscape. This is a foreseeable stressor the substrate's posture already answers rather than a new requirement: trust anchored to a vendor or jurisdiction is fragile under distribution restriction; trust anchored to the operator's Genesis root is not. The substrate composes with lawful process while defeating silent/unaccountable control, and it depends on no single model's continued availability (multi-source inference is the operational expression; per-operator trust root the structural one). No structural change implied — noted so the reasoning trail records that the stressor was anticipated.

---

## Summary of nominated actions

| # | Doc | Type | Weight |
|---|-----|------|--------|
| E1 | INFERENCE-ROUTING-DISCIPLINE | Additive note | Confirms + adds data |
| E2 | DEPENDENCY-POSTURE | Additive note + cadence trigger | Raises priority (hedge → baseline) |
| E3 | SUBSTRATE-HARDENING-CEREMONY | Additive note | Confirms premise, sharpens cadence |
| E4 | SOVEREIGN-KINSHIP-PRIMITIVES (+ DEPENDENT-SOVEREIGNTY xref) | New scenario **+ design decision** | Possibly additive primitive |
| E5 | CRYPTO-SOVEREIGNTY-AND-LEGAL-PROCESS | Additive note | Confirms posture |

Plus two candidate CLAUDE.md heuristics (staged, pending N-instances test) — see brief.
