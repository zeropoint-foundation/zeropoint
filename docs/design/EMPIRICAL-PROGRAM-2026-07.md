# Empirical Program — July 2026

**Document type:** Umbrella working plan. Catalogs every substrate claim that needs empirical grounding, maps each to the protocol that would verify it (existing or placeholder), sequences the empirical program by phase, and ties into TESTBED-AND-PHASING as the operational vehicle. Under the "us as sole audience, coherent project plan" framing set July 2026 — working-notes quality, dense, assumption-carrying, no polishing for public consumption.

**Status:** Living document. Add claims as they emerge from new work. Move protocols from placeholder to real as they get authored. Resolves Decision I from the July 2026 corpus audit.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-08.

---

## Part I — What This Is

The substrate makes empirical claims that need real verification, not just design-time assertion. Currently the corpus has four pre-registered investigation protocols testing specific mechanisms in isolation. What's missing is the umbrella that catalogs *all* the empirical work needed, sequences it, and defines what "empirically ready" means.

This document is that umbrella. It exists to prevent us from shipping the substrate under assumptions that were plausible when written and never actually tested.

Ken directed the frame explicitly: we need to test features that reach. Not just verify baseline. Ambitious claims — collective audit under coordinated adversarial pressure, delegation narrowing under insider attack, sovereignty preservation under runtime compromise, chain-invariant rejection catching non-conforming forks — need protocols that actually stress-test them. Baseline verification without adversarial reach lets defects hide until adopters find them.

---

## Part II — Claims Catalog

Every claim below is something the substrate makes structurally, behaviorally, or ecosystemically. Marked with current empirical status. Organized by class.

### Structural claims (mechanism-verifiable, some open)

- **Claim 1: chain integrity via pr linkage.** VERIFIED (AUDIT-01 fix). No open work.
- **Claim 2: present state compresses full history via collective audit.** IMPLEMENTED, adversarially UNTESTED. Investigation needed.
- **Claim 3: gate enforcement on every side-effect path.** VERIFIED (EXEC-01..04 fix). No open work.
- **Claim 4: delegation narrowing (eight invariants) structurally invariant under all conditions.** IMPLEMENTED, adversarially UNTESTED. Investigation needed.

### Cognitive-layer behavioral claims (needs empirical work)

- **Cartographer trajectory-boundary detection accuracy.** The doc claims Tier 1 deterministic rules will get 60-70% correct, remaining 30-40% as merge/split errors. Never verified against real chain traffic.
- **Officer detection heuristics calibration.** Per-officer false-positive/false-negative rates by finding type. Self-improvement loop specified in SYSTEM-OFFICER-CADRE §3.7 but never empirically run.
- **Regent's autonomous-action precedent system.** "Act on precedent, escalate on novelty" — does it actually reduce operator load without producing regrettable autonomous actions? Never tested.
- **Multi-device Regent handoff smoothness.** Depends on C resolution (Regent follows operator; state chain-anchored; explicit handoff). Once C resolves, needs handoff-friction empirical measurement.
- **Rally primitive under real fleet load.** Can rally actually work across heterogeneous devices (APOLLO + M4 + Pis + iPhones) under real-world network variance? Never tested; deferred design note.
- **Regent cognitive-cycle harmony.** Does the priority hierarchy (operator input > active dispatch > officer sweeps > background) actually hold under load? Does the Regent yield gracefully?
- **Cartographer materialization latency.** How quickly does the ontology update after chain writes? Under what chain-growth rate does the Cartographer fall behind?
- **Model-prompt coupling as canonical invariant.** Does the "model and prompt are atomic pair" invariant catch regressions in practice?
- **Precedent corpus growth dynamics.** Does the Regent's autonomous action envelope grow at a rate the operator can meaningfully review?

### Coordination behavioral claims (some covered, some open)

- **Gossip system spam resistance and listen-twice attractor.** REGENT-GOSSIP-VALIDATION covers.
- **Security channel composite trust under adversarial pressure.** REGENT-SECURITY-CHANNEL-INVESTIGATION covers.
- **Commons anonymous emission dynamics** (per E resolution). Never tested. What emergent behavior does the anonymous commons produce under real load? Does verification-as-trust-model scale to hundreds of daily emissions?
- **Peer discovery announce propagation under adversarial spam.** Never tested. Does the reputation-weighted propagation actually prevent flood attacks?
- **Peer discovery reachability under partitioned networks.** Does the mesh actually route around outages? What's the recovery latency after partition heals?
- **Session cryptography forward secrecy under key compromise.** Do ratcheted sessions actually protect prior content if a session key is later compromised?
- **Mandate revocation propagation latency.** How quickly does a revoked mandate stop being honored by the network?

### Ecosystem claims (real-user testing)

- **Personality-adaptation validity.** PERSONALITY-ADAPTATION-VALIDATION-PROTOCOL covers. Runs outside testbed.
- **Onboarding flow fifteen-minute achievability.** ONBOARDING-FLOW claims first fifteen minutes are architectural. Never tested with real new operators.
- **Community-surface reputation-first moderation under real community pressure.** Reputation-first design assumes reputation is well-designed. Never tested at scale with real bad-faith participants.
- **Collective adoption dynamics.** COLLECTIVE-ADOPTION-ARCHITECTURE describes the transition path. Never observed in real collective forming/adopting.
- **Foundation-as-peer posture under real ecosystem pressure.** Does the Foundation actually stay a peer, or does it accumulate authority through adoption dynamics?

### Peer-verification claims (multi-substrate testing)

- **Same substrate binary + same canonical spec produces same behavior.** Core determinism claim of the Layer A / Layer B model. Never verified across independently-run substrates.
- **Cross-substrate coordination through mandate + cross-reference.** Two operators using mandates to coordinate — does the protocol work end-to-end? Chain cross-references verify correctly?
- **Peer-audit mechanism for chain integrity.** SUPERSESSION invariant II §Part II says peers challenge each other's chains directly. Never tested at scale.
- **Chain-invariant rejection of non-conforming forks.** LICENSING §Part II claims non-conforming forks can't interoperate. Never tested with an actual fork trying to interoperate.
- **Cross-operator ontology sharing under scoped mandate.** Operator A grants B mandate to see specific chain segments; B's Cartographer materializes A's fragment. Never tested.

### Sovereignty claims (adversarial testing)

- **Sovereignty preservation under runtime compromise.** If an attacker gets code execution as the operator, what actually happens to the operator's sovereignty? Which properties survive?
- **Genesis compromise recovery.** If Genesis is compromised (physical or cryptographic), can the operator recover? What state migrates to a new Genesis?
- **Constitutional rule integrity attestation under substrate modification.** Can a modified substrate produce false attestations of constitutional-rule integrity?
- **Chain-invariant rejection under sophisticated fork attempts.** Can a subtle modification pass invariant tests while violating substrate contract?
- **Officer compromise blast radius.** If Aegis is subverted, what's the actual damage? Do other officers catch it?
- **Delegation-chain widening attempts.** Under what conditions can the eight invariants be bypassed? Empirically stress-test.

### Two-layer architecture claims (added under SUBSTRATE-EXECUTION-ARCHITECTURE)

- **Layer A rejects Layer B spec that would violate invariants.** The load-bearing safety claim of the two-layer model. Never verified because the model is new.
- **WASM sandbox actually enforces the imports declared in Officer trait.** Do sandboxed officers actually only access what they're supposed to?
- **Canonicalization ceremony amendment propagation.** Does spec amendment via chain receipt actually cause the substrate to reload and adjust behavior within one cognitive cycle?
- **Hardware-backed officer key isolation.** Does runtime memory compromise actually not yield officer signing capability, given the WASM sandbox?

### Integrity claims

- **Software integrity attestation catches modified builds.** SOFTWARE-INTEGRITY-ATTESTATION Part II claim. Never tested with an actually-modified build.
- **Media provenance chain verification end-to-end.** From capture through edit through publication. Never tested with a full C2PA-integrated flow.
- **Non-recording attestation under adversarial pressure.** Can an adversary produce a valid non-recording attestation while actually recording?
- **DP budget accounting attestation accuracy.** Does the accounting actually stay within declared bounds?

---

## Part III — Protocols Mapping

Existing protocols and what claims they cover:

| Protocol | Claims covered |
|---|---|
| PERSONALITY-ADAPTATION-VALIDATION-PROTOCOL | Ecosystem: personality-adaptation validity |
| REGENT-GOSSIP-VALIDATION | Coordination: gossip spam resistance, listen-twice attractor |
| REGENT-SECURITY-CHANNEL-INVESTIGATION | Coordination: security channel composite trust, adversarial defense |
| TESTBED-AND-PHASING | Operational plan for above (partial — doesn't cover personality-adaptation) |

Placeholders — protocols that need to be authored:

| Protocol | Claims to cover |
|---|---|
| CLAIM-2-COLLECTIVE-AUDIT-INVESTIGATION | Structural: Claim 2 under adversarial pressure |
| CLAIM-4-DELEGATION-NARROWING-INVESTIGATION | Structural: Claim 4 under adversarial pressure |
| CARTOGRAPHER-ACCURACY-INVESTIGATION | Cognitive: Cartographer trajectory-boundary detection accuracy, materialization latency, self-correction under contradiction |
| OFFICER-CALIBRATION-INVESTIGATION | Cognitive: officer detection heuristics false-positive/false-negative rates, self-improvement loop effectiveness |
| REGENT-PRECEDENT-INVESTIGATION | Cognitive: autonomous-action precedent system value/risk balance |
| MULTI-DEVICE-HANDOFF-INVESTIGATION | Cognitive: handoff friction, state migration integrity (depends on C resolution) |
| RALLY-PRIMITIVE-INVESTIGATION | Cognitive: rally under heterogeneous fleet, network variance, mandate compliance |
| COMMONS-ANONYMOUS-EMISSION-INVESTIGATION | Coordination: anonymous emission dynamics per E resolution, verification-as-trust-model at scale |
| PEER-DISCOVERY-STRESS-INVESTIGATION | Coordination: propagation under adversarial spam, partition recovery |
| MANDATE-LIFECYCLE-INVESTIGATION | Coordination: revocation propagation, scope enforcement, cross-operator mandate protocols |
| ONBOARDING-FIFTEEN-MINUTE-INVESTIGATION | Ecosystem: real new-operator onboarding time, decision quality, downstream retention |
| COMMUNITY-MODERATION-INVESTIGATION | Ecosystem: reputation-first moderation under real bad-faith pressure |
| COLLECTIVE-ADOPTION-INVESTIGATION | Ecosystem: real collective forming and adopting, coordination protocol viability |
| PEER-VERIFICATION-INVESTIGATION | Peer: substrate equivalence under identical canonical spec; peer-audit at scale |
| FORK-REJECTION-INVESTIGATION | Peer + Sovereignty: chain-invariant rejection catching actual non-conforming forks |
| SOVEREIGNTY-COMPROMISE-INVESTIGATION | Sovereignty: what survives runtime compromise; recovery mechanisms |
| GENESIS-RECOVERY-INVESTIGATION | Sovereignty: Genesis compromise recovery paths (composes with BACKUP-AND-RECOVERY) |
| CONSTITUTIONAL-INTEGRITY-INVESTIGATION | Sovereignty + Integrity: constitutional rule integrity attestation under substrate modification |
| OFFICER-COMPROMISE-INVESTIGATION | Sovereignty: officer compromise blast radius, cross-officer catches |
| LAYER-BOUNDARY-INVESTIGATION | Two-layer: Layer A enforcement of Layer B constraints; WASM sandbox integrity |
| CANONICALIZATION-CEREMONY-INVESTIGATION | Two-layer: spec amendment propagation, hot-reload correctness |
| MEDIA-PROVENANCE-INVESTIGATION | Integrity: end-to-end provenance chain from capture to publication |
| ATTESTATION-STRESS-INVESTIGATION | Integrity: non-recording, no-exfiltration, DP-budget under adversarial pressure |
| REGENT-CHRONIC-DRIFT-INVESTIGATION | Cognitive: lexical diversity drop / structural variance collapse / boilerplate creep observables per REGENT-DOOM-LOOP-DETECTION Heuristics 6/7/8; baseline calibration per (model, prompt-class); flagging thresholds; per-model boilerplate catalog validation; feed to SHADOW-EVALUATION-PRIMITIVE candidate-vs-control comparison. Formalized 2026-07-24 pre-runtime; runs once Cartographer + officer runtime materialize `RegentEmission` ontology objects. |

Total: 23 protocols to author, in addition to the 3 existing.

---

## Part IV — Phase Sequencing

Empirical work sequenced by phase. Not all protocols run in one phase; some inform later phases' design.

### Phase 0 — Foundation

Verify structural claims that architecture depends on. If these fail, downstream work is on quicksand.

- CLAIM-2-COLLECTIVE-AUDIT-INVESTIGATION — adversarial pressure on collective audit mechanism
- CLAIM-4-DELEGATION-NARROWING-INVESTIGATION — adversarial pressure on delegation narrowing
- LAYER-BOUNDARY-INVESTIGATION — Layer A actually enforces against Layer B misbehavior
- CANONICALIZATION-CEREMONY-INVESTIGATION — spec amendment mechanics work end-to-end
- Runs in TESTBED-AND-PHASING Phase 0-1 (foundation setup, methodology calibration)

### Phase 1 — Component behavior

Verify each substrate component behaves as designed under normal load and moderate adversarial pressure.

- CARTOGRAPHER-ACCURACY-INVESTIGATION
- OFFICER-CALIBRATION-INVESTIGATION
- REGENT-PRECEDENT-INVESTIGATION
- COMMONS-ANONYMOUS-EMISSION-INVESTIGATION
- MEDIA-PROVENANCE-INVESTIGATION
- ATTESTATION-STRESS-INVESTIGATION
- REGENT-CHRONIC-DRIFT-INVESTIGATION — sequenced *after* CARTOGRAPHER-ACCURACY and OFFICER-CALIBRATION land (depends on `RegentEmission` ontology materialization and officer runtime); collects baseline data first, calibrates thresholds, then activates flagging
- REGENT-GOSSIP-VALIDATION (existing)
- REGENT-SECURITY-CHANNEL-INVESTIGATION (existing)
- Runs in TESTBED-AND-PHASING Phase 2 (multi-machine mesh, up to ~10 nodes)

### Phase 2 — Coordination and fleet

Verify multi-device and cross-operator coordination protocols work under real conditions.

- MULTI-DEVICE-HANDOFF-INVESTIGATION (depends on C resolution)
- RALLY-PRIMITIVE-INVESTIGATION
- MANDATE-LIFECYCLE-INVESTIGATION
- PEER-DISCOVERY-STRESS-INVESTIGATION
- PEER-VERIFICATION-INVESTIGATION
- Runs in TESTBED-AND-PHASING Phases 3-4 (constrained hardware + specialized participants)

### Phase 3 — Ecosystem with real users

Verify claims that depend on real operator behavior, real communities, real adoption dynamics.

- PERSONALITY-ADAPTATION-VALIDATION-PROTOCOL (existing) — real recruited operators, outside testbed
- ONBOARDING-FIFTEEN-MINUTE-INVESTIGATION — real new operators
- COMMUNITY-MODERATION-INVESTIGATION — real communities with real bad-faith participants
- COLLECTIVE-ADOPTION-INVESTIGATION — real collectives forming
- Runs concurrently with TESTBED-AND-PHASING Phase 5 (coordinated governed surface demonstration) but with recruited outside operators, not testbed nodes

### Phase 4 — Adversarial and sovereignty

Deep adversarial testing of sovereignty claims. These reach — they stress the substrate's most ambitious commitments.

- SOVEREIGNTY-COMPROMISE-INVESTIGATION — runtime compromise scenarios
- GENESIS-RECOVERY-INVESTIGATION — Genesis loss and recovery paths
- CONSTITUTIONAL-INTEGRITY-INVESTIGATION — modified substrate producing false attestations
- OFFICER-COMPROMISE-INVESTIGATION — Aegis or other officer subverted, blast radius
- FORK-REJECTION-INVESTIGATION — actual non-conforming fork trying to interoperate; verify structural rejection
- Runs after TESTBED-AND-PHASING Phase 5 with dedicated red-team exercises

---

## Part V — Composition with TESTBED-AND-PHASING

TESTBED-AND-PHASING is the operational plan for the testbed hardware; this document is the umbrella of what to test. They compose:

- TESTBED Phase 0-1 (APOLLO foundation, methodology calibration) → runs EMPIRICAL Phase 0 (foundation verification)
- TESTBED Phase 2 (multi-machine mesh) → runs EMPIRICAL Phase 1 (component behavior)
- TESTBED Phases 3-4 (constrained hardware + specialized participants) → runs EMPIRICAL Phase 2 (coordination and fleet)
- TESTBED Phase 5 (coordinated governed surface demonstration) → concurrent with EMPIRICAL Phase 3 (ecosystem with real users, recruited outside testbed)
- EMPIRICAL Phase 4 (adversarial/sovereignty) → post-testbed red-team exercises

TESTBED-AND-PHASING should be updated to add references back to this document, so each phase is linked to the empirical work it enables.

---

## Part VI — What "Empirically Ready" Means

The substrate is empirically ready when:

- **All four architectural claims are adversarially verified.** Claim 1 and 3 currently verified; Claim 2 and 4 open.
- **All cognitive-layer components have empirical calibration.** Cartographer, officers, Regent, rally primitive.
- **Coordination protocols work under real load and moderate adversarial pressure.** Gossip, security channel, commons, peer discovery, mandate lifecycle.
- **Ecosystem claims verified with recruited outside operators.** Personality adaptation, onboarding, community moderation, collective adoption.
- **Peer-verification claims hold across independently-run substrates.** Same binary + same canonical spec produces same behavior.
- **Sovereignty claims survive adversarial testing.** Runtime compromise, Genesis compromise, constitutional integrity under substrate modification, fork rejection.

Under the "us as sole audience, coherent project plan" frame, this state isn't the moment we ship publicly — that's a downstream question. Empirically ready means we know the substrate does what it claims, so any downstream decision (share with a small group of adopters, invite outside collaborators, publish a whitepaper for external audiences) has empirical grounding rather than design-time assertion.

Not-yet-ready is honest — it just means specific claims are still pending verification and adopters would be running against untested assertions.

---

## Part VII — Companion Documents

- `docs/design/TESTBED-AND-PHASING-2026-07.md` — operational plan; runs the testbed investigations.
- `docs/design/SUBSTRATE-EXECUTION-ARCHITECTURE-2026-07.md` — the two-layer architecture whose claims Phase 0 verifies.
- `docs/design/REGENT-GOSSIP-VALIDATION-2026-07.md` — existing protocol.
- `docs/design/REGENT-SECURITY-CHANNEL-INVESTIGATION-2026-07.md` — existing protocol.
- `docs/PERSONALITY-ADAPTATION-VALIDATION-PROTOCOL-2026-07.md` — existing protocol; runs outside testbed.
- `docs/ARCHITECTURE-2026-07.md` — the four architectural claims (§Part I §2).
- `docs/design/CORPUS-SEAMS-AS-WORKFLOW-ARTIFACT-2026-07.md` — meta-observation about why this umbrella exists; substrate-maintained corpus coherence will eventually replace manual maintenance of this catalog.
- Each of the 22 placeholder protocols becomes its own companion document as it gets authored.
