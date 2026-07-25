# Substrate Execution Architecture — July 2026

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.9 (two-layer architecture), §II.10 (composition contracts), and Part III (Layer B axioms). Canonical claims live in KEEL; this doc provides the implementation-level detail and design rationale. Layer A's canonical realization at the operating-system level lives in `SUBSTRATE-FORM-2026-07.md`; the observation tier that composes with Layer A lives in `OBSERVATION-PLANE-2026-07.md`.

**Document type:** Architectural note. Specifies the two-layer execution model that resolves several standing questions in the corpus: how officers activate, where authority lives, what the Cartographer is structurally, how the substrate self-adjusts within bounded invariants, and what canonical form load-bearing behavior takes. Consolidates decisions made in the July 2026 corpus audit session (Decision A on key hierarchy, the Cartographer reshape, the determinism principle, and Ken's decisions on Layer A/B separation and WASM-as-spec-substrate).

**Status:** Design note. Sets the shape for the substrate's execution model going forward. Supersedes portions of EXECUTION-AUTHORITY-MODEL-2026-07's "two authorities" framing and resolves the officer signing keys open question from SYSTEM-OFFICER-CADRE-2026-06 §8. Names the questions still open at the end.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-08. Framing amendment 2026-07-10.

> **2026-07-10 framing amendment.** This document defines the Layer A / Layer B split at the substrate-behavior level. It does not specify *what Layer A's canonical realization is at the OS level*. That question is resolved by `docs/design/SUBSTRATE-FORM-2026-07.md`: Layer A's canonical form is **Sovereign Form** — a reproducibly-built NixOS-based operating system with operator-controlled hardware trust chain (measured boot, sealed FDE, hardware Genesis). Non-canonical Forms (Appliance, Companion) run the same Layer A / Layer B substrate stack but with reduced trust-chain reach, honestly disclosed. `docs/KEEL-2026-07.md` Part XIV declares this. The two-layer split in this doc is Form-invariant; the reach of what Layer A can defend depends on Form. The observation plane specified in `docs/design/OBSERVATION-PLANE-2026-07.md` is a Layer A tier whose reachable surfaces vary by Form.

---

## Part I — What This Is

The corpus has accumulated several questions that touch the substrate's execution model: how officers wake and act, who directs whom, what the Cartographer is structurally, how the substrate's behavior can change without eroding what makes it work. This document specifies the architecture that answers those questions coherently.

The shape is two layers with a hard boundary between them. Layer A is compiled runtime — the substrate binary that enforces the invariants defining what ZeroPoint is. Layer B is spec-driven behavior — WASM modules and canonical data records that the runtime loads, executes, and observes at operator direction. Amendments happen at Layer B via chain-anchored canonicalization ceremonies. Layer A is not amendable except by shipping a new substrate binary through the release chain.

The substrate self-adjusts within Layer A's guardrails. Operator sovereignty operates at Layer B. Peer verification is precise at both layers because everything is content-addressed and deterministic.

---

## Part II — The Two Layers

**Layer A — Runtime invariants (compiled Rust host).**

Baked into the substrate binary. Not amendable via canonicalization ceremony. The substrate binary is what it is; a substrate with different Layer A is a different substrate. Layer A holds the conservation laws that define ZeroPoint structurally.

What lives at Layer A:

- Constitutional rules: HarmPrincipleRule and SovereigntyRule, atomic evaluation at the gate.
- Chain integrity: hash linkage, signature verification, append-only semantics, receipt schema enforcement.
- Delegation narrowing: the eight invariants for chain verification.
- Genesis-as-single-root of the key hierarchy (per Decision A: one Genesis per sovereign, human-controlled, all keys derive).
- Cryptographic primitives: Ed25519 signing, Blake3 hashing, HKDF-SHA256 derivation, XChaCha20-Poly1305 AEAD.
- The requirement that officers hold hardware-backed Genesis-certified keys and that officer findings are signed.
- The gate: no code path skips constitutional evaluation.
- The Officer trait interface (the shape any WASM officer module must conform to).
- The WASM runtime itself and the imports it exposes to sandboxed modules.
- The receipt schema and wire format.
- The canonicalization ceremony structure (how Layer B amendments actually get anchored).

Amending Layer A means shipping a new substrate binary. That release goes through the release chain per SOFTWARE-INTEGRITY-ATTESTATION-2026-07: build hash, source hash, declared capabilities, multi-party signing ceremony, community verification. Ken cannot canonicalize his way through a Layer A property. If Ken wants a Layer A change, he ships (or forks and ships) a new binary that carries the change, and the community decides whether to adopt.

**Layer B — Spec-driven behavior (WASM modules + canonical data records).**

Chain-anchored, operator-signed, content-addressed, executed within Layer A's constraints. Amendable via canonicalization ceremonies. This is where legitimate operator sovereignty operates.

Two kinds of Layer B artifacts:

- **Canonical data records** — thresholds, cadences, ontology definitions, term boundaries, officer charter fields, presentation defaults. Chain-anchored as signed receipts in MessagePack canonical form. Deterministic parsing.
- **WASM modules** — officer implementations, Cartographer projection rules, cognitive-layer strategies. Chain-anchored via content hash referenced in canonicalization receipts. Deterministic execution.

Both are operator-signed. Both amendable via ceremony. Both peer-verifiable.

**The runtime enforces Layer A regardless of what Layer B says.** A Layer B spec that would violate Layer A is rejected by the runtime at parse or load time. There is no override flag, no ceremony that gets you through a conservation law, no operator-signed path around the gate. This is what protects the substrate from operator fuckery — sovereignty operates at Layer B; identity is defended at Layer A.

---

## Part III — Layer A Detail

The compiled substrate binary provides the following structural properties, non-amendable:

**Cryptographic primitives.** Ed25519 signing, verification, key derivation. Blake3 hashing. HKDF-SHA256 key derivation. XChaCha20-Poly1305 AEAD. Chosen once; ships in the binary; not swappable via canonicalization.

**Chain integrity enforcement.** Every receipt append validates: signature verifies against the actor's expected key, hash-link to previous receipt is intact, receipt structure conforms to the schema, timestamps are monotonic within reasonable bounds. Invalid receipts are rejected structurally.

**Gate atomicity.** Every side-effecting action passes through the gate. No code path in the compiled substrate skips it. Constitutional rules (HarmPrincipleRule, SovereigntyRule) evaluate first, atomically, on every gated action. WASM modules cannot bypass because they cannot access the side-effect primitives (network, disk, hardware key) except through host-mediated interfaces that gate-check on the way out.

**Delegation narrowing.** The eight invariants verify on every delegation chain. Any violation rejects the entire chain. Non-configurable, non-amendable.

**Genesis-as-root.** All key derivation and certification traces to a single Genesis keypair per sovereign. Ceremonial control of Genesis (single-human or M-of-N) is up to the sovereign at ceremony time; the substrate's requirement that all authority flows from one Genesis is Layer A.

**Officer trait interface.** The Rust host defines the trait every officer WASM module must implement. Function signatures, import declarations, export declarations, resource metering constraints, sandbox capabilities. The trait is Layer A because it's the contract between the host's structural guarantees and the module's domain logic. A WASM module that doesn't conform to the trait is rejected at load time.

**Officer key management.** Officer signing keys are hardware-backed, Genesis-certified per provisioning receipt. The host holds the key handles and mediates signing. Officer WASM modules cannot access the private key material — they invoke the host's signing interface, which validates and signs.

**Receipt schema.** The wire format for receipts is specified by whitepaper §4.1. The host validates every receipt on emission against the schema. Non-conforming receipts are rejected structurally. WASM modules cannot emit malformed receipts because emission goes through the host.

**Canonicalization ceremony structure.** The mechanism by which Layer B amendments happen — the ceremony steps, signature requirements, cooling periods, chain-anchoring shape — is Layer A. Ceremony amendments would require substrate-binary shipping.

**Two-tier release path.** Layer A changes ship as substrate binaries via the release chain (Foundation-signed or community-signed release receipts, reproducible builds, chain-of-trust verification). Layer B changes ship as canonicalization receipts on the operator's own chain.

---

## Part IV — Layer B Detail

Chain-anchored, operator-signed spec that the runtime reads and executes within Layer A's constraints.

**Canonical data records.** Thresholds, cadences, ontology definitions, term boundaries, officer charter fields. Authored in Markdown + front-matter (scaffolding); tooling extracts structured records; operator signs canonicalization receipts referencing content hashes. Runtime reads via the canonical spec index.

Example — an officer charter data record:

```
type: officer_charter
id: aegis-charter
supersedes: null
officer_role: constitutional_trajectory_monitoring
activation_model: continuous
minimum_finding_interval_secs: 30
signal_inputs:
  - cartographer_trajectory_objects
  - steward_integrity_findings
  - sentinel_security_findings
  - forge_operational_findings
  - cleo_governance_findings
escalation:
  critical_severity_preempts_regent: true
wasm_module_hash: blake3:abc123...
```

The `wasm_module_hash` field references the officer's Layer B code — the WASM module implementing Aegis's domain logic.

**WASM modules.** Officer implementations, Cartographer projection rules, cognitive-layer strategies. Compiled from source (Rust, AssemblyScript, C, or any WASM-target language) into deterministic WASM binaries. Content-hashed via Blake3. Referenced by canonicalization receipts. Loaded by the runtime, verified against the appropriate Layer A trait, executed inside the sandbox.

**Amendment.** Ken authors a new spec (data record or WASM module). Tooling compiles/extracts to canonical form; produces content hashes. A ZEP is drafted per SUPERSESSION-FRAMEWORK-2026-07. Community review. Ken canonicalizes with a signed receipt referencing the new artifact hashes. Chain records. Runtime observes; fetches artifacts by hash; verifies against Layer A constraints; loads. Behavior adjusts.

**Peer verification.** Two substrates hold "the same" Layer B behavior if they hold the same canonicalized spec hashes. Comparison is precise — hash equality, not semantic equivalence argument.

---

## Part V — Officers as Composed Structures

Every officer is a composed structure: Rust host (Layer A) + WASM core (Layer B), coordinated through the Officer trait interface.

**Host side (Layer A):**

- Officer trait interface definition
- WASM runtime (Wasmtime or equivalent)
- Hardware-backed key access — host holds the key handle, exposes a signing interface to the module
- Chain-reader interface — bounded, read-only
- Ontology-reader interface — bounded, read-only
- Charter-config-reader interface — access to this officer's canonical spec fields
- Finding-emission interface — host validates and signs before append
- Sandbox lifecycle — spawn, run, terminate, resource-meter
- Signature-over-emission — host signs findings before they land on chain; WASM never touches the private key
- Receipt schema enforcement — host structurally rejects any finding that doesn't conform

**WASM core (Layer B):**

- Activation model — when to wake (continuous vs. event-driven vs. periodic)
- Signal-input processing — how to interpret other officers' findings, chain events, ontology state
- Domain-specific detection logic — what patterns this officer watches for
- Threshold evaluation — what constitutes a finding worth emitting
- Finding content construction — what fields the finding carries, how they're populated
- Cadence logic — internal timing between findings, deduplication of repeated patterns

**The host provides capabilities; the WASM core provides judgment.** The host guarantees structural properties (findings are signed, well-formed, correctly linked into the chain). The WASM guarantees domain-specific behavior (what this officer actually watches for and reports).

**Why composition rather than pure WASM:** the officer's signing key is hardware-backed. Hardware operations require host-level system calls that the WASM sandbox structurally cannot make. If an officer were pure WASM, it would either hold key material in-module (defeating hardware-backing) or ask the host to sign on its behalf (which means part of the officer is host-side). There is no version of "pure WASM officer" that preserves the hardware-key security property.

**Amendment flow for an officer:**

1. Author or tune the officer's WASM module.
2. Tooling compiles to WASM, hashes, prepares canonicalization artifacts.
3. Draft a ZEP proposing the amendment.
4. Community review per SUPERSESSION.
5. Operator signs canonicalization receipt referencing new WASM module hash and updated charter data records.
6. Runtime observes; verifies signature to Genesis; verifies new WASM against Officer trait interface (imports, exports, resource declarations match); verifies charter data against Layer A constraints; terminates current WASM instance; loads new module; calls initialization; resumes cognitive-cycle integration.

All chain-anchored. All within one cognitive cycle. Deterministic. Peer-verifiable.

**Same pattern for all officers.** Steward, Sentinel, Forge, Cleo, Aegis all conform to the same Officer trait interface. Different WASM cores implement different domain logic.

---

## Part VI — The Cartographer

The Cartographer is composed with a WASM core, same pattern as officers, but with one critical difference: **the Cartographer has no independent signing key.**

**Why no key:** the Cartographer's output is a projection of the chain. Chain is truth; ontology is understanding. If the Cartographer became a signing authority, its judgments would carry cryptographic weight the substrate would defend — but its judgments depend on inference, model choices, threshold calibration. Two Cartographers with different WASM cores against the same chain would produce different ontologies. Making one of those an authority means model choices become governance events. That's the wrong shape.

The Cartographer is infrastructure. Its outputs are advisory. Its state (the ontology) is a cache the substrate can rebuild from the chain.

**Host side (Layer A):**

- Cartographer trait interface (analogous to Officer trait but with no signing capability)
- Chain-reader interface for materialization
- Ontology-store handle (local database, disposable)
- Sandbox lifecycle
- No key handle, no signing interface — the host does not expose signing to the Cartographer WASM

**WASM core (Layer B):**

- Trajectory boundary detection logic
- Ontology object construction rules
- Correction and consistency-maintenance logic
- Relationship inference

**What the Cartographer produces:** local ontology state (in `ontology.db` per the current design), plus unsigned local-bus events for state changes. If chain-anchored ontology changes need to happen (operator corrections, canonicalization ceremonies), they're signed by the operator or the officer producing the finding, never by the Cartographer.

**Officer attestations reference the chain, not the Cartographer.** When Aegis emits a finding about trajectory drift, she references the chain receipts that constitute the trajectory (via `receipt_refs` in the ontology object). The Cartographer's classification was her working substrate but not her source of authority. If the ontology.db is suspect, rebuild from chain; Aegis's finding logic reads the rebuilt ontology and either produces the same finding or corrects itself.

**Amendment for the Cartographer:** same as officers minus signing. Canonicalize a new WASM module hash for the Cartographer role. Runtime loads. Ontology gets rebuilt from chain against the new logic. No signature migration needed because the Cartographer never signed anything.

---

## Part VII — Amendment Ceremonies

Layer B amendments happen via chain-anchored canonicalization ceremonies. Ceremony rigor scales with the risk of the amendment.

**Tier 1 — Adjustments within a component's declared parameters.**

Example: raising Aegis's minimum finding interval from 30s to 60s. Ken signs a canonicalization receipt updating the charter data record. Immediate effect. Low ceremony because the amendment is bounded to declared adjustable parameters.

**Tier 2 — Component logic changes.**

Example: swapping Aegis's WASM module for a differently-tuned version. Ken drafts a ZEP; community review period per SUPERSESSION; Ken signs canonicalization receipt referencing new module hash; runtime performs graceful handoff. Elevated ceremony because behavior changes are more consequential.

**Tier 3 — Component identity changes.**

Example: replacing Aegis with a different officer for the constitutional-trajectory monitoring role. Requires a ZEP demonstrating the replacement conforms to the invariant "constitutional-trajectory monitoring must be performed by an officer with hardware-backed Genesis-certified key." Multi-signature from all provisioned sovereign devices; 14-day cooling period; active final confirmation. Same pattern as the constitutional amendment ceremony in `regent-gossip-and-evolution-2026-07` §Design Decision 5.

**Tier 4 — Invariant amendments.**

Not a canonicalization ceremony. A new substrate binary shipped through the release chain. Community verification. Adopters choose whether to run.

The runtime rejects any canonicalization amendment that would cross a tier boundary. Trying to amend Aegis's charter such that findings are unsigned is rejected at parse — that would be a Tier 4 change, not achievable via canonicalization.

---

## Part VIII — Peer Verification

Two substrates hold "the same" behavior if:

- Same Layer A: same substrate binary hash (verifiable via SOFTWARE-INTEGRITY-ATTESTATION release chain).
- Same Layer B: same set of canonicalized artifact hashes.

Hash comparison at every layer. No semantic equivalence argument required.

When a peer observes a finding on the chain, they can verify:

- The finding is signed by a specific officer key.
- That key is certified by the operator's Genesis via a chain-anchored provisioning receipt.
- The signing officer WASM module is a specific canonicalized hash.
- That module conforms to the Layer A Officer trait (invariant guarantee).
- Therefore the finding is produced by a substrate whose specific configuration is precisely knowable.

Cross-substrate peer verification of "does your Aegis and mine produce compatible findings?" becomes concrete: check the canonicalized WASM hashes. Same hash = same behavior (WASM determinism). Different hash = different tuning, which may or may not compose.

This is what makes the substrate an ecosystem rather than a set of similar but semantically-drifting deployments.

---

## Part IX — What This Supersedes

- **EXECUTION-AUTHORITY-MODEL-2026-07's "two authorities" framing** evolves to two layers plus canonicalization authority. Regent and Forge are executors within Layer B, not authorities. The operator is the authority — over Layer B via canonicalization ceremonies, and over Layer A via release-chain adoption decisions.

- **SYSTEM-OFFICER-CADRE-2026-06 §8 open question on officer signing keys** resolves to option (c) with composition: officers hold their own hardware-backed Genesis-certified keys, mediated by the host, with WASM cores implementing domain logic.

- **ONTOLOGY-AND-CARTOGRAPHER-2026-07's treatment of the Cartographer as a first-class actor with `ActorId::System("cartographer")` and signed receipts** is superseded: Cartographer is infrastructure, no independent signing authority, outputs are local cache and unsigned events.

- **The four descriptions of officer activation** across SYSTEM-OFFICER-CADRE, EXECUTION-AUTHORITY-MODEL, TRAJECTORY-AWARE, and CLAUDE.md resolve to: each officer's activation model is declared in its canonical charter (Layer B data record). Aegis's continuous cadence is a canonical claim, not a Regent directive.

The prior documents remain valuable for their domain-specific analysis; this document is the anchor for the execution-model questions they collectively raised.

---

## Part X — Open Design Decisions

Named openly so the substrate can pick them up and address them structurally rather than through workflow drift.

1. **Exact scope of Layer A.** This document names the load-bearing invariants but the compiled/spec boundary needs precise definition per subsystem. Which parts of the gate are compiled? Which parts are canonical? The Officer trait is compiled — but the interface definition style (WIT? Protobuf?) is open.

2. **WASM runtime choice.** Wasmtime, Wasmer, or custom. Trade-offs on maturity, footprint, deterministic execution guarantees. Deterministic-mode WASM configuration required.

3. **Canonical spec index structure.** How the runtime discovers what canonical artifacts to load. A chain-anchored index receipt with an ordered list of Layer B artifact hashes? Per-role receipts (one for Aegis, one for Steward, etc.)? Trade-offs on amendment granularity.

4. **Authoring toolchain.** Markdown + front-matter to WASM/canonical-data pipeline. Which source languages compile cleanly to deterministic WASM. Tooling for extracting data records from front-matter.

5. **Ceremony tier calibration.** Which specific amendments fall into which tier. This document sketches four tiers but the exact boundaries between them are per-role decisions.

6. **Migration path for existing substrate code.** The current substrate has officers as compiled Rust. Migrating them to composed (host + WASM core) is real engineering. Sequencing and testing.

7. **Cartographer trait interface.** Analogous to Officer trait but without signing. Definition, capability surface, resource metering.

8. **Regent's composition.** Some of the Regent's cognitive-layer logic is Layer B (specific reasoning strategies, memory management heuristics). Some is Layer A (core cognitive-cycle scaffolding, delegation-check invariants). Where the line goes for the Regent needs specification.

9. **Tenant tool composition.** Per TOOL-OPACITY-AND-CAPABILITY-CLASSES, tools are already candidates for WASM sandboxing. Aligning tenant tools with the composed pattern.

---

## Part XI — Companion Documents

- `docs/ARCHITECTURE-2026-07.md` — canonical architecture; this document specifies the execution model that architecture assumes.
- `docs/EXECUTION-AUTHORITY-MODEL-2026-07.md` — the prior "two authorities" framing this document evolves. Retained for its analysis of the problems the current model addresses.
- `docs/design/SYSTEM-OFFICER-CADRE-2026-06.md` — officer domains and roles. Signing keys open question resolved here.
- `docs/design/ONTOLOGY-AND-CARTOGRAPHER-2026-07.md` — Cartographer role. Superseded on the "first-class actor with signing authority" claim; retained for the ontology design.
- `docs/design/TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md` — Aegis's role. Her continuous activation is a Layer B canonical claim under this model.
- `docs/design/SUPERSESSION-FRAMEWORK-2026-07.md` — the ZEP mechanism through which Layer B amendments become canonical.
- `docs/design/SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md` — the release chain that governs Layer A substrate binary distribution.
- `docs/design/ENCRYPTED-STORAGE-ARCHITECTURE-2026-07.md` — key hierarchy that the officer key model extends.
- `docs/design/MULTI-DEVICE-OPERATION-2026-07.md` — device provisioning ceremony pattern that the officer key provisioning extends.
- `docs/design/LICENSING-AND-INTEGRITY-2026-07.md` — the chain-invariant rejection mechanism that catches forked substrates violating Layer A.
- `docs/design/TOOL-OPACITY-AND-CAPABILITY-CLASSES-2026-07.md` — the sandboxing pattern the officer composition extends.
- `docs/design/regent-gossip-and-evolution-2026-07.md` — the constitutional amendment ceremony pattern this document generalizes for Tier 3 amendments.
- `docs/design/CORPUS-SEAMS-AS-WORKFLOW-ARTIFACT-2026-07.md` — the pattern this document is one instance of: substrate self-maintenance replacing manual coherence work.
