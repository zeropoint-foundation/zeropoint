# Testbed and Phasing — July 2026

**Document type:** Operational plan. Captures the ZeroPoint testbed inventory, node and participant allocation, phased build-up with go/no-go gates, design gaps whose resolution is deliberately deferred until phase findings inform them, and the product engineering explicitly out of investigation-phase scope.

**Status:** Draft. **Revised 2026-07-27** to reflect the two-role sovereign topology per `HARDWARE-ROLE-SEPARATION-2026-07.md` — APOLLO gains an explicit Regent-role designation; Raspberry Pi allocation gains an explicit Sentinel-role designation distinct from the "constrained-hardware persona" testbed usage; Phase 4 gains a Sentinel↔Regent split gate.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-08 (revised 2026-07-27).

---

## Part I — Why Phased

The empirical work is what drives design decisions in several places — rally, sensor access, coordinated-surface coordination. Each of those design notes is deliberately deferred until phase findings inform them, rather than committed upfront and then bent by data.

Phasing gates a specific failure mode: build the full 25-node testbed first, discover in Phase 5 that Phase 0's methodology was miscalibrated, redo work at scale rather than at Phase 1 cost. Each phase validates its own assumptions before the next phase's hardware and complexity come online. The phasing IS the discipline; deleting it produces the same substrate with less honest empirical grounding underneath.

Investigation phase throughout — real product engineering (mobile apps, production-grade Watcher firmware, production VM provisioning tooling) is out of scope, listed explicitly in Part VI.

---

## Part II — Hardware Inventory

APOLLO. Primary coordinator, 64GB RAM. Ken's daily-driver Mac Mini (M4 Pro) — both source-of-truth for source code and runtime home for the ZP daemon. Hosts multiple ZP nodes as VMs from Phase 1 onward. Retains the coordinator role through every phase; other machines join as peers. **Regent-role sovereign designation** (per `HARDWARE-ROLE-SEPARATION-2026-07.md`) once its Regent stand-up ceremony completes per `mac-mini-regent-standup-checklist-2026-07-27.md`; hosts LLM inference, LoRA adapter workload, and the in-process output observer for the two-node sovereign topology.

M4 Pro MacBook. 24GB RAM. Compute infrastructure — hosts a local Ollama inference resource that other nodes can rally, replacing cloud inference for cost and sovereignty reasons once Phase 2 begins. Doubles as sensor gateway host (camera, microphone) once specialized participant provisioning lands in Phase 4.

Older MacBook. ~16GB RAM. Takes the ARTEMIS-designated clean-install and portable-system role from operator memory — Touch ID sovereignty testing runs here, and this is the machine that verifies onboarding flow from a clean environment without APOLLO's accumulated state.

Raspberry Pis (2-3 units). 8GB each, ARM64. Two distinct roles under the two-role topology per `HARDWARE-ROLE-SEPARATION-2026-07.md`: (a) **Sentinel-role sovereign** — one Pi 5 stood up per `pi5-sovereign-standup-checklist-2026-07-17.md` becomes the network-adjacent Sentinel node, coordinating with the ASUS router for allowlist enforcement, destination monitoring, and chain-anchored egress attestation. This Pi is not a constrained-hardware persona; it is a role-specialized sovereign at the Sentinel-role Tier 0 entry point. (b) **Constrained-hardware persona testbed** — the remaining 1-2 Pis test whether the substrate holds up on single-board computers with a fraction of APOLLO's resources (the original framing for Phase 3). Native install, not VM.

Ubuntu laptop. x86_64 architecture. Adds architectural diversity — catches endianness, alignment, or platform assumptions the Apple Silicon testbed would miss. One or two nodes.

SenseCap Watcher. ESP32-S3 based. Currently sends inference requests to cloud by default; Phase 4 reprograms it to disable cloud dependency and rally inference from M4 instead. Specialized sensor gateway with camera plus display.

iPhones (multiple). iOS. Scoped-capability participants — sensor gateway (camera, microphone, location, biometric attestation), alert display, notification recipient. Not full ZP nodes without eventual iOS-app product engineering; investigation-phase participation via minimal companion mechanism.

Samsung Galaxy S5. Android, ~2014 vintage. Legacy-constrained mobile — does the substrate meaningfully work on decade-old hardware? Custom ROM (LineageOS) likely required for anything substantial.

---

## Part III — Node and Participant Allocation

Rough allocation across phases, subject to Phase 1 calibration:

APOLLO hosts 3-4 nodes in Phase 1 as VMs — the methodology-calibration substrate — and scales to 6-8 in later phases as coordinator plus adversarial peers plus community participants.

M4 Pro hosts 2-3 general ZP nodes alongside the local Ollama inference resource. The rally target for other machines. Sensor gateway role (camera, microphone) provisioned in Phase 4.

Older MacBook hosts 2-3 nodes with heterogeneous personas — some honest, some adversarial framings that don't require constrained-hardware realism. Also the clean-install verification substrate.

Raspberry Pi allocation follows the two-role split named in Part II. One Pi 5 hosts the Sentinel-role sovereign — native install, adjacent to the ASUS router, running `tools/sentinel/zp_sentinel/` under Linux-systemd profile plus the chain-anchor discipline established in the Pi 5 stand-up ceremony. The remaining 1-2 Pis host constrained-operator persona nodes as originally planned. Sentinel Pi does not double as a constrained-operator persona; its role is bounded and specialized.

Ubuntu laptop hosts 1-2 nodes as the x86_64 diversity anchor.

Watcher operates as one specialized participant — sensor gateway rallying M4 for inference. Not a general ZP node; its role is purely capture and display under mandate.

Each iPhone operates as one scoped-capability participant, provisioned by APOLLO or M4 with narrow mandate — sensor access, alert display, notification receipt. Under this framing the iPhone is an extension of the operator's coordinated control rather than an autonomous participant.

S5 operates as one legacy-constrained scoped participant with the same posture as the iPhones, sized to what its constrained hardware actually supports.

Full-scale total for the Phase 5 demonstration: roughly 20-24 general ZP nodes plus 4-6 specialized participants.

---

## Part IV — Phase Structure

### Phase 0 — Foundation

APOLLO alone, one ZP node, cloud inference. Establish the base VM template that later phases replicate from. Verify chain, gate, officer cadre, Cartographer, Regent daemon, and cloud-inference mandate all functional. Collect baseline metrics on chain growth rate, memory footprint per node, cloud inference cost per hour of typical operation.

Go/no-go: does a single ZP node run stably under cloud inference with a resource footprint that scales sensibly to N nodes? If no, resolve foundation issues before adding complexity — the gap surfaces during single-node run and gets much harder to diagnose once the substrate is a mesh.

Deliverable: baseline metrics report — footprint per node, cost per hour, chain size growth, plus the reusable VM template later phases build on.

### Phase 1 — Small subset methodology calibration

APOLLO alone, 3-4 nodes as separate VMs, mesh transport in-process. Scenarios: baseline cooperative operation, first cross-node chain sync, one honest and one adversarial persona.

Purpose: methodology calibration. What does trust bootstrap actually look like when observed? What noise dominates? What's the measurement resolution? What do the officers actually report? Aegis in particular is exercised for the first time — does he notice what he was designed to notice, or does his signal drown in noise?

Go/no-go: does the methodology produce interpretable findings, or are we drowning in noise? Refine before scaling — running Phase 2 on top of a miscalibrated methodology multiplies the miscalibration.

Deliverable: methodology calibration report — what to measure, at what resolution, and how the officers' findings compose into interpretable signal.

### Phase 2 — Multi-machine mesh

Adds M4 Pro and older MacBook, roughly 8-10 nodes, real cross-machine mesh transport. Cloud inference optional at this point — shifting to M4-hosted local inference via rally lets Phase 2 start exercising the rally primitive that later phases depend on.

Scenarios: security channel investigation baseline runs (per its own pre-registration). Gossip validation baseline runs (per its own pre-registration). First-pass adversarial variants of both. First real cross-substrate mandate exercises.

Go/no-go: do the trust bootstrap and adversarial defense findings from Phase 1 replicate under real mesh? Significant divergence means the in-process simulation was misleading and future methodology needs adjustment. Small divergence is expected and informs Phase 3 planning.

Deliverable: first-pass findings for the security channel and gossip investigations, plus early rally-primitive observations that feed the deferred rally design note.

### Phase 3 — Constrained hardware and architectural heterogeneity

Adds 2-3 Pis and the Ubuntu laptop, roughly 12-14 nodes. Real architecture diversity comes online. Substrate assumptions about hardware get exercised. Does the substrate hold up on Pi-class hardware? Does x86_64 catch endianness or alignment bugs the Apple Silicon testbed missed? Do Pi-hosted adversarial personas behave believably — the constrained compute actually changes attack economics in ways that only real hardware exposes?

Go/no-go: does the substrate hold up on constrained hardware? If not, either the substrate needs work or the constrained-operator personas need to be reframed for realism — either finding is load-bearing.

Deliverable: architectural validation findings — what parts of the substrate depend on hardware assumptions, and whether those assumptions hold.

### Phase 4 — Specialized participants + Sentinel↔Regent split gate

Adds Watcher plus mobile devices, roughly 18-20 participants total. Watcher reprogrammed to disable cloud dependency and provisioned as sensor gateway rallying inference from M4. iPhones and S5 provisioned as scoped-capability participants via minimal companion mechanism (URL schemes, WebKit views, or minimal companion app — whichever proves lowest-effort while sufficient).

**Sentinel↔Regent split gate (added 2026-07-27):** this phase also stands up the two-role sovereign topology per `HARDWARE-ROLE-SEPARATION-2026-07.md`. Pi 5 Sentinel comes online per `pi5-sovereign-standup-checklist-2026-07-17.md` (adjacent to the ASUS router over Ethernet, mirror mode or VLAN tap, allowlist enforcement active). APOLLO Regent comes online per `mac-mini-regent-standup-checklist-2026-07-27.md` (in-process output observer wired, adapter scaffolding in place, Secure Enclave-derived Genesis bound). The two nodes exchange the mesh handshake and cross-reference each other's chain segments. This is a first-class exercise of the role-separation topology and the substrate primitives that support it (independent Genesis roots, cross-referenced chain events, complementary observer visibility).

Scenarios: sensor access capability exercised. Provenance capture with real hardware. Rally with heterogeneous participants. Cross-network operation — mobile on cellular, rest on WiFi. **Sentinel-detected egress anomaly triggers a chain-anchored defensive-swap request against the Regent; observer-agreement confidence threshold verified.**

Go/no-go: does the sensor access capability class actually work in practice? Does the rally primitive compose meaningfully with heterogeneous participants? **Does the Sentinel↔Regent split cleanly separate attack surfaces without introducing coordination brittleness?** Any of these findings shapes the deferred design notes.

Deliverable: sensor access and rally validation findings, **Sentinel↔Regent topology empirical grounding for the two-role framing in `HARDWARE-ROLE-SEPARATION-2026-07.md`**, plus enough empirical grounding to write the two deferred design notes with confidence.

### Phase 5 — Coordinated governed surface demonstration

Full testbed, roughly 22-26 participants. Coordinated control demonstration: operator on APOLLO orchestrates the full governed surface. Rally-based compute, sensor-gateway participation, community coordination across the mesh, security channel active, gossip system running, mandates issued and revoked, officers reporting continuously.

This phase is a demonstration artifact, not just validation. Show what coordinated sovereign control across a heterogeneous substrate actually looks like at meaningful scale — the artifact matters as much as the findings.

Deliverable: the demonstration itself as a public artifact, plus the third deferred design note now empirically grounded.

---

## Part V — Design Gaps and Resolution Path

Three design notes are deliberately deferred until phase findings inform them:

Rally primitive. Exercised in Phase 2 for compute mandates across machines. The design note (GOVERNED-RESOURCE-RALLY-2026-07.md) gets written after Phase 2 first-pass findings expose how mandate lifecycle, resource contention, and cross-machine authorization actually behave. Phase 2 operates with an ad-hoc mandate structure that gets replaced by the codified design once findings inform it.

Sensor access capability class. Exercised in Phase 4 with Watcher and mobile sensor gateway provisioning. The design note (SENSOR-ACCESS-CAPABILITY-2026-07.md) gets written after Phase 4 exposes how consent, capability scope, and provisioning actually work with real hardware.

Governed surface coordination. Demonstrated in Phase 5. The design note (GOVERNED-SURFACE-COORDINATION-2026-07.md) gets written after Phase 5 has empirical grounding for what coordinated control across the entire governed surface actually means as a capability, not as an aspiration.

Writing these notes now — before phase findings — would commit to specifications the empirical work might invalidate. Writing them empirically-grounded produces better designs. The tradeoff is that Phase 2 and Phase 4 run with less codified structure than they eventually will have; that's acceptable because the codification comes from what they teach.

---

## Part VI — Deferred Product Engineering

Explicitly out of investigation-phase scope:

Real iOS ZP app. Full mobile ZP node requires actual iOS app development — Swift, App Attest integration, Secure Enclave sovereignty provider, App Store review. Weeks-to-months of product work. Investigation phase uses scoped-capability companion mechanism instead.

Real Android ZP app. Same reasoning for Android — Kotlin, StrongBox integration, Play Integrity attestation. Investigation phase uses scoped-capability companion mechanism.

Production-grade Watcher firmware. Full reprogramming with production-grade firmware attesting build identity is embedded engineering. Investigation phase can use network-block-at-router stopgap or minimal firmware modification sufficient to disable cloud dependency.

Production VM provisioning tooling. Managing 20+ VMs across multiple Macs via Virtualization.framework properly requires real tooling — inventory, health monitoring, mesh transport wiring, per-VM identity provisioning. Investigation phase uses manual setup or ad-hoc scripts.

Mobile companion mechanism at production quality. iOS URL schemes, WebKit views, or a minimal companion app for scoped-capability participation — investigation-phase minimum viable, not production polish.

Each of these becomes a product commitment after investigation phase validates the substrate is worth productizing. Naming them as deferred here is the honest posture — they exist as future work, not as gaps the investigation should chase.

---

## Part VII — What Can Be Dropped Without Breaking the Arc

Ubuntu laptop. Nice for x86_64 diversity but not critical. If the machine is unstable or Ken doesn't want to spare it, skip Phase 3's Ubuntu portion; the Pis carry constrained-hardware coverage alone.

Watcher firmware reprogramming. If reprogramming turns out to be more work than budgeted, treat the Watcher as network-isolated at router level for investigation phase and defer real firmware work to product phase. The Watcher still participates as a sensor gateway; its cloud dependency just gets neutered externally.

Mobile companion mechanism. If not ready by Phase 4, Phase 5 demonstration proceeds without mobile participants; they get added later. The demonstration remains compelling; it just doesn't tell the mobile story yet.

Full 22-26 participant scale in Phase 5. The demonstration is compelling even at 15-18 participants. Better to run stable at reduced scale than unstable at target scale.

None of these drops invalidate the phase gates before them — they just narrow the Phase 5 demonstration's specific shape.

---

## Part VIII — Composition

This plan composes with the existing investigation plans and supporting design notes:

REGENT-SECURITY-CHANNEL-INVESTIGATION-2026-07.md — the security channel investigation runs its baseline in Phase 2 and gets fuller adversarial scenarios in Phases 4-5.

REGENT-GOSSIP-VALIDATION-2026-07.md — the gossip validation runs its baseline in Phase 2 and gets peer-diversity variants in Phase 3 once constrained hardware comes online.

TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md — Aegis is exercised throughout, particularly Phase 2 onward as adversarial patterns scale.

MULTI-DEVICE-OPERATION-2026-07.md — the per-device capability scope structure this plan uses to allocate personas across machines and phones.

COMMUNITY-COORDINATION-ON-ZEROPOINT-2026-07.md — the surface Phase 5 demonstrates coordinated control over.

PERSONALITY-ADAPTATION-VALIDATION-PROTOCOL-2026-07.md — the pre-registration discipline that all phase investigations inherit.

EMPIRICAL-PROGRAM-2026-07.md — the umbrella that catalogs every substrate empirical claim, maps existing and needed protocols, and sequences empirical work by phase. This testbed plan is the operational vehicle for Phase 0-2 of the empirical program (foundation verification, component behavior, coordination and fleet); Phase 3 (ecosystem) runs with recruited operators outside the testbed; Phase 4 (adversarial and sovereignty) runs as post-testbed red-team exercises.

The three deferred design notes (rally, sensor access, coordinated surface) will be linked here as they land, each with a note pointing back to the phase whose findings shaped them.
