# Officer Lens Declarations — Inside-Out Lens Retrofit

**Document type:** Tier 2 canonical elaboration. Formalizes each officer's attention scope as a `lens:declared:*` instance under `LENS-DISCIPLINE-2026-07.md`. Direction: **inside-out** (substrate self-observation at each officer's declared scope).

**Motivation:** Ken's June 2026 articulation in `docs/handoffs/officer-heartbeat-handoff-2026-06.md`: *"Each officer (Steward, Sentinel, Forge) is an independent observer with its own lens."* Predates LENS-DISCIPLINE formalization but exhibits the discipline's structure exactly. This document retrofits that proto-lens formulation as formal chain-anchor-able lens declarations.

**Date:** 2026-07-24. Ken authored the proto-lens framing (2026-06); Claude retrofitted to LENS-DISCIPLINE schema.

**Composes with:** `LENS-DISCIPLINE-2026-07.md` (schema this doc uses), `OBSERVER-COHERENCE-DISCIPLINE-2026-07.md` (each officer lens is a coherence-class member when multiple officers observe overlapping state), `SUBSTRATE-COORDINATION-DISCIPLINE-2026-07.md` (KEEL III.25 — officer signal quality is coordination hygiene), officer implementation specs (Steward, Sentinel, Forge, Cleo, Aegis).

## Framing

The officer cadre implements the substrate's autonomic observation layer. Each officer has a declared attention scope — a specific slice of substrate state they watch continuously and produce findings about. That scope is exactly what LENS-DISCIPLINE calls a lens: focus (what to attend to), dimensions (categories of observation), keyword_composition (the receipt patterns and event classes that invoke the officer's attention), transformation_question (the coherence question the officer answers per sweep).

Officer lenses are **inside-out** — the substrate observing itself at declared scope. Distinguished from outside-in lenses (external framings composed with substrate) and view-in lenses (UI projections). Each officer's chain-anchored heartbeat is functionally `lens:applied:officer_<name>:<sweep_id>` under the discipline; findings are lens-invocation outputs.

Retrofit rather than rewrite: existing officer receipts (`officer:std:*`, `officer:sen:*`, `officer:forge:*`, `officer:cleo:*`, `officer:aegis:*`) remain canonical. This spec documents how they map to LENS-DISCIPLINE schema so downstream tooling (Cartographer ontology projection, cross-lens coherence, silent-lens detection) can treat them as first-class lens instances without changing the officer implementation.

## Steward — `lens:declared:officer_std`

- **`lens_id`**: `officer_std`
- **`focus`**: chain integrity + vault coherence + config hygiene (the substrate's structural truth surface)
- **`dimensions`**: hash-linkage validity, signature presence, chain-tail continuity, vault key set coherence, config-file schema conformance, drift detection
- **`keyword_composition`**: [chain integrity, hash linkage, signature, chain silence, chain burst, vault, config, hygiene, drift, entries examined, entries verified]
- **`transformation_question`**: *"is the substrate's structural truth surface intact and coherent?"*
- **`cross_references`**: KEEL §II.2 (chain integrity discipline), `CHAIN-READ-CANARY-DISCIPLINE-2026-07.md` (composes for freshness), `OBSERVER-COHERENCE-DISCIPLINE-2026-07.md` §Class 1 (chain readers coherence class — Steward is a member), `VAULT-KEY-SOVEREIGNTY-COMPOSITION-2026-07.md`

Receipt patterns Steward emits (mapped to `lens:applied:officer_std:*`):
- `officer:std:heartbeat` — sweep-cycle marker (base cadence signal)
- `officer:std:integrity:integrity_verified` — clean pass (verified state)
- `officer:std:integrity:hash_discontinuity` — hash-linkage violation (Critical divergence)
- `officer:std:integrity:chain_link_broken` — chain-link failure (Critical divergence)
- `officer:std:integrity:signature_invalid` — signature-check failure (Error divergence)
- `officer:std:integrity:chain_silence` — chain-tail staleness (Warning; known false-positive class per task #15/#22)
- `officer:std:integrity:chain_burst` — chain-tail unusual velocity (Warning)
- `officer:std:integrity:unsigned_entry_ratio` — chain-signing hygiene (Warning)
- `officer:std:vault:*` — vault hygiene findings

## Sentinel — `lens:declared:officer_sen`

- **`lens_id`**: `officer_sen`
- **`focus`**: security surface (identity anomalies, credential drift, unauthorized access patterns, listener anomalies)
- **`dimensions`**: identity assertion validity, credential rotation cadence, access pattern anomaly, listener authorization, credential drift across namespaces, shadow credential detection
- **`keyword_composition`**: [unauthorized listener, credential drift, shadow credential, identity anomaly, access pattern, unauthorized access, credential rotation, port binding, listener PID, security posture]
- **`transformation_question`**: *"is the substrate's security surface unmodified by unauthorized activity, and is credential state coherent?"*
- **`cross_references`**: `SUBSTRATE-HARDENING-CEREMONY-2026-07.md` (Sentinel is the adversarial-hardening actor per that spec), `SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md` (III.24 — Sentinel operates within aligned blindness — sees credential surface, not values), `OBSERVER-COHERENCE-DISCIPLINE-2026-07.md` §Class 3a (process/network coherence class — Sentinel is a member), §Class 4 (vault key listers — Sentinel's shadow_credential detection is a member)

Receipt patterns Sentinel emits (mapped to `lens:applied:officer_sen:*`):
- `officer:sen:heartbeat`
- `officer:sen:security:unauthorized_listener` — listener not in port registry (known noise class per P1.2 refactor; benign classifications now emit `unregistered_known_app` at Info)
- `officer:sen:security:unregistered_known_app` — benign listener class (browser helper, IDE helper, messaging client, system daemon) at Info per P1.2 (2026-07-11)
- `officer:sen:security:shadow_credential` — genuinely unusual variable name appearing across multiple vault namespaces (Warning; real drift signal after 2026-07-24 task #12 refactor)
- `officer:sen:security:generic_config_field_name` — generic config field name (API_KEY, TOKEN, URL, HOST, DB_HOST, REGION, TIMEOUT, ...) appearing across multiple vault namespaces at Info (routine multi-tool config, not drift) per task #12 (2026-07-24)
- `officer:sen:security:credential_in_key_name` — plaintext secret pattern detected in key name (Error)
- `officer:sen:security:*` — additional security findings

## Forge — `lens:declared:officer_forge`

- **`lens_id`**: `officer_forge`
- **`focus`**: tool and process operational health (lifecycle events, process state, governance advancement)
- **`dimensions`**: tool lifecycle stage (monitored / hardened / governed), process liveness, resource consumption, governance posture advancement, tool port binding, log growth
- **`keyword_composition`**: [tool lifecycle, process health, port binding, governance advancement, monitored, hardened, governed, log growth, resource usage, crash loop, tool state]
- **`transformation_question`**: *"are the substrate's tools and processes operating within declared discipline and advancing correctly?"*
- **`cross_references`**: `TOOL-GOVERNANCE-LIFECYCLE-2026-07.md`, `OFFICER-ACTION-SURFACES-2026-07.md` (Forge has an action surface distinct from observation — this lens is the observation side), `OBSERVER-COHERENCE-DISCIPLINE-2026-07.md` §Class 3a (process/network) and §Class 3b (filesystem posture) — Forge is a member of both

Receipt patterns Forge emits (mapped to `lens:applied:officer_forge:*`):
- `officer:forge:heartbeat`
- `officer:forge:*` — tool lifecycle findings, process health findings

## Cleo — `lens:declared:officer_cleo`

- **`lens_id`**: `officer_cleo`
- **`focus`**: governance narration + delegation + gate decisions + authority chain integrity
- **`dimensions`**: active delegation count, revoked/expired delegation count, gate decision outcomes (allowed/denied), authority chain hop count, delegation scope narrowing, governance posture derivation
- **`keyword_composition`**: [delegation, gate decision, authority chain, capability grant, capability revoke, authority chain valid, governance narration, unsigned governance, delegation scope, authority hop]
- **`transformation_question`**: *"is the substrate's governance surface narrating truthfully — do delegations, gate decisions, and authority chains cohere with the chain evidence?"*
- **`cross_references`**: KEEL §II.13 P8 (delegation-narrowing invariant), `SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md` (cross-sovereign delegations that Cleo narrates), `OBSERVER-COHERENCE-DISCIPLINE-2026-07.md` §Class 1 (Cleo's delegation walk is a Class 1 member — reads chain via search_by_keyword)

Receipt patterns Cleo emits (mapped to `lens:applied:officer_cleo:*`):
- `officer:cleo:heartbeat`
- `officer:cleo:governance:authority_chain_valid`
- `officer:cleo:governance:*` — delegation, gate-decision, and authority findings

## Aegis — `lens:declared:officer_aegis`

- **`lens_id`**: `officer_aegis`
- **`focus`**: constitutional-trajectory monitoring — best-effort detection of misaligned trajectories relative to declared operator constitutional invariants
- **`dimensions`**: trajectory coherence, precedent alignment with declared invariants, constitutional-boundary crossings, drift patterns across substrate lifetime, sustained trajectory divergence
- **`keyword_composition`**: [trajectory, constitutional invariant, misaligned, precedent divergence, boundary crossing, sustained drift, coherence loss, alignment]
- **`transformation_question`**: *"is the substrate's trajectory over time coherent with declared constitutional invariants, and if divergence detected, is it explicit or drift?"*
- **`cross_references`**: `TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md` §VI.1 (Aegis's spec source), `IMPROVEMENT-LOOP-DISCIPLINE-2026-07.md` (Aegis observations feed the improvement loop's evidence corpus), `CIRCUIT-BREAKER-2026-07.md` (sustained constitutional divergence triggers escalation)

Implementation status: **v1 landed 2026-07-24** per task #24. Aegis is registered in the officer cadre, emits heartbeats via the sweep runner, and produces trajectory-scope findings. v1 scope is officer-cadre cadence coherence — best-effort detection of officers whose heartbeats have gone silent past declared thresholds. Full trajectory-level detection per TRAJECTORY-AWARE §VI.1 remains deferred pending Cartographer materialization of the trajectory ontology.

Receipt patterns Aegis emits (mapped to `lens:applied:officer_aegis:*`):
- `officer:aegis:heartbeat` — sweep-cycle marker
- `officer:aegis:trajectory:coherent` — all observed officers within cadence (Ok)
- `officer:aegis:trajectory:awaiting_cadre_history` — insufficient observation history (Info, cold-start case)
- `officer:aegis:trajectory:silent_officer:{name}` — specific officer silent past 2× or 4× cadence (Warning / Critical)
- `officer:aegis:trajectory:divergent:warning` — summary finding, at least one officer at Warning
- `officer:aegis:trajectory:divergent:critical` — summary finding, at least one officer at Critical

Aegis composes with OBSERVER-COHERENCE-DISCIPLINE by attending to a distinct axis: coherence discipline cross-checks *what* officers see; Aegis cross-checks *whether* officers see. Together they cover both dimensions of observation health. Post-Cartographer, Aegis's dimensions extend to trajectory alignment, precedent divergence, and constitutional-boundary crossings — the current v1 substrate-cadence subset is the observable slice that composes without Cartographer infrastructure.

## Composition properties emerging from declaring officers as lenses

Naming each officer as a lens surfaces properties that were implicit before:

1. **Officer coherence checks are inside-out lens coherence checks.** OBSERVER-COHERENCE-DISCIPLINE §Class 1 already names Steward's chain_growth and Steward's chain_integrity as Class 1 members. Under this doc's retrofit, those are both invocations of `lens:applied:officer_std:*`. Class 1 coherence divergence is a divergence between two invocations of the same lens — a specific fault class the discipline can detect.

2. **Silent-lens-over-long-window is observable per officer.** LENS-DISCIPLINE §3 names "silent lens over long window is as significant as loud lens over short window." Under officer lenses, this means: if Steward's heartbeats stop firing, or if a specific finding class (like `chain_integrity:integrity_verified`) goes silent for hours, that's a trajectory-scope observer signal. Not currently detected structurally; enabled by this retrofit + long-window observer implementation.

3. **Cross-officer keyword overlap surfaces coherence-class membership.** When Steward and Sentinel both attend to "chain" keywords, they're both members of Class 1 (chain readers). When Sentinel and Forge both attend to "port binding" keywords, they're both members of Class 3a (process/network). Keyword-composition overlap is the structural signal for coherence-class registration, computable from the lens declarations.

4. **Cartographer materialization of lens ontology becomes possible per officer.** Each officer's finding history is walkable as `lens:applied:officer_<name>` receipt chain. Cartographer projects the lens graph showing which officers attended what pattern over time, which patterns went silent, which officers drifted from their declared focus.

5. **Regent's cognitive input plane can query officer lenses.** For any Regent cycle, the Cognitive Input Plane can ask "which officer lenses are relevant to this cycle's context?" by matching current work keywords against officer keyword_compositions. Officer findings enter Tier 2 context selectively rather than all-at-once — attention priority per officer per cycle.

## Non-goals

- **Not modifying officer implementation.** This is a documentation retrofit; existing officer code, receipt schemas, and cadence are unchanged.
- **Not chain-anchoring new lens receipts for existing officer emissions.** Existing `officer:*:heartbeat` and `officer:*:finding:*` receipts already serve the invocation-evidence role. Chain-anchored `lens:declared:officer_*` receipts (per LENS-DISCIPLINE §2) are the new addition — one per officer, operator-signed at substrate initialization ceremony.
- **Not comprehensive keyword coverage.** The keyword compositions above are the load-bearing subsets. Extension via canonicalization ceremony as officer capabilities evolve.
- **Not enforcement.** Officer lens declarations describe what each officer attends to; they don't enforce that officers stay within scope. Enforcement is coherence discipline + circuit breaker (sustained out-of-scope emissions would surface as coherence divergence).

## Open positions

- **`lens:declared:officer_*` chain-anchoring ceremony.** When is each officer's lens declared? Options: (a) at substrate initialization (part of Genesis ceremony), (b) at officer-cadre startup (each officer declares its own lens as first emission on cold start), (c) at canonicalization ceremony (batched with other Layer B canonical declarations). Prefer (b) — each officer owns its lens declaration; substrate init doesn't need to know officer implementation details.
- **Retrofitting historical officer emissions.** Existing chain history has millions of `officer:*:*` receipts. Should they be retroactively projected as `lens:applied:*` invocations for coherence discipline lookup? Prefer no — forward-only application; historical receipts stand as-is; new receipts optionally carry both officer:*:* and lens:applied:* framing.
- **Officer-lens conflict declarations.** Are there cases where two officers' lenses conflict (prescribe contradictory transformations on overlapping keywords)? Currently no — officer scopes are declared non-overlapping. If Aegis's trajectory-monitoring overlaps with Steward's chain-integrity monitoring in some cases, `lens:conflicts:officer_std:officer_aegis` would formalize the tension. Empirical observation deferred.
- **Regent as officer with its own lens.** Regent has attention scope (cognitive discipline sandwich per COGNITIVE-INPUT-PLANE + COGNITIVE-SELF-OBSERVER). Should Regent be declared as `lens:declared:officer_regent`? Regent is architecturally distinct from the officer cadre, but the lens discipline applies. Deferred; treat as separate arc.

## What composes from here

Immediate design work:
1. Chain-anchor `lens:declared:officer_std / officer_sen / officer_forge / officer_cleo / officer_aegis` receipts at first officer-cadre startup after this doc lands.
2. Add composition note to OBSERVER-COHERENCE-DISCIPLINE §Class 1 naming officer lens invocations as coherence class members explicitly.
3. Extend Cartographer's ontology projection to include lens nodes when lens receipts land on chain.

Near-term implementation:
1. Cadre-startup lens declaration emission (small — one receipt per officer at cold start).
2. Lens-application receipt emission on officer sweeps (optional — existing officer:*:heartbeat already serves the role; lens:applied receipts add discipline-namespace parallelism if desired).
3. Silent-lens detection for officer lenses — long-window observer queries `lens:applied:officer_*` receipt cadence, flags officers whose expected-cadence emissions have gone silent.

## Framing note

Ken's June 2026 articulation — *"Each officer is an independent observer with its own lens"* — was the seed. LENS-DISCIPLINE (2026-07-21) formalized the primitive. This retrofit (2026-07-24) closes the loop: officer proto-lens formulation becomes formal chain-anchor-able lens declarations under the discipline's schema.

The five officer lens declarations are the first concrete **inside-out** lens instances outside of the substrate-self-observation abstraction. Cognitive-tools mapping is the outside-in flagship; cognitive-system-approximation is the inside-out theoretical flagship; officer lenses are the inside-out **operational** flagship — every officer sweep is a lens invocation, chain-anchored, coherence-checkable, silence-detectable.

Officer cadre + LENS-DISCIPLINE + OBSERVER-COHERENCE-DISCIPLINE compose into the substrate's structural attention discipline for autonomic observation. Regent + cognitive discipline sandwich + LENS-DISCIPLINE compose into the substrate's structural attention discipline for cognitive work. Same discipline, two application surfaces. Load-bearing symmetry.
