# Executable Artifacts — Opportunity Mapping

**Document type:** Design intent / opportunity mapping. **Not** a Tier 2 canonical elaboration — it elaborates no KEEL section, though it bears directly on §II.19, §II.8 and Part V. Per A1 the negative test applies: this document argues for a reading of primitives that already exist rather than specifying new ones, so it is an opportunity mapping and says so.

**Date:** 2026-07-27.

**Source:** A 9m37s YouTube explainer on WebAssembly's 2025 position (`youtu.be/VQHRUQDCh_Q`, structured capture at `docs/mindmaps/webassembly-2025-shift-2026-07.json`), read against a direct survey of WASM and WASI usage across `docs/` and `crates/` performed the same day.

**Attribution:** The external framing — Wasm 3.0's built-in garbage collection, WASI 0.2 and the component model stabilizing in 2025, the container comparison, the Akamai/Fermyon acquisition — is the video's. The substrate reading, the two-class module split, the app-store decomposition, the regulatory posture and the open positions are the ZeroPoint reading, drafted by Claude at the operator's request. The decision to refuse an app store, and the regulatory reasoning behind it, are Ken's.

**Composes with:** `EXTENSION-SURFACE-2026-07.md` (the existing Tier 2 elaboration of Part V — this document argues its trait families and manifest are reaching toward what WIT worlds already express), `QUARANTINE-PLANE-2026-07.md` (the admission ceremony an executable artifact passes through, and the home of the existing WASI open position), `ARTIFACT-LIBRARY-2026-05.md` (content-addressed signed artifacts — the claim here is that an executable artifact is not a new object but the same one), `REPRODUCIBILITY-CEREMONY-2026-07.md` (what a deterministic component makes possible that a service call cannot), `PEER-TRUST-ANCHOR-2026-07.md` (its non-goals are why no catalogue is needed; its bootstrapping open position is the one gap a catalogue would have covered), `CRYPTOGRAPHIC-SOVEREIGNTY-AND-LEGAL-PROCESS-2026-07.md` (where the refusal recorded in §Regulatory posture should land as a standing non-goal), `DECENTRALIZED-TRANSPORT-OPPORTUNITY-MAPPING-2026-07.md` (the availability question this document isolates is that document's carrier question, reached from the other end), `ARCHITECTURE-2026-04.md` (the deferral this document reopens, and the reason it was correct when made), `DEPENDENCY-POSTURE.md` (`wasmtime` is already catalogued; this raises its weight).

---

## Formal lens declaration

Per `LENS-DISCIPLINE-2026-07.md`:

- **`lens_id`**: `executable_artifacts`
- **`focus`**: what becomes possible when a signed, content-addressed artifact is executable — and which of the roles an app platform normally assumes the substrate must structurally refuse
- **`dimensions`**: determinism, content addressing, capability mediation, admission ceremony, provenance, reproducibility, distribution, curation, namespace authority, regulatory role, module class
- **`keyword_composition`**: [wasm, wasi, component model, wit, sandbox, module, plugin, extension, app, artifact, executable, deterministic, reproducible, capability, host import, fuel, registry, catalogue, app store, publish, admit, run someone else's code]
- **`transformation_question`**: *"is this artifact executed for its result, or for the proof of its result — and which of naming, curation, trust, availability and rent is anyone assuming the substrate provides?"*
- **`cross_references`**: KEEL §II.6, §II.8, §II.9, §II.10, §II.19, §IV.3, §IV.6, §V.1–V.3, §VI, §XIII.2; `EXTENSION-SURFACE-2026-07.md`; `QUARANTINE-PLANE-2026-07.md`; `ARTIFACT-LIBRARY-2026-05.md`; `REPRODUCIBILITY-CEREMONY-2026-07.md`; `DECENTRALIZED-TRANSPORT-OPPORTUNITY-MAPPING-2026-07.md`

Directional: **outside-in**. Expected edges: `lens:composed:executable_artifacts:decentralized_transport` — both fire on the question of where an artifact lives and who is allowed to have removed it.

---

## Framing

**1. The deferral was correct, and its reopen condition has fired.** `ARCHITECTURE-2026-04.md` states the position plainly — *"What Phase 0 deliberately does not do. It does not architect anything. It does not move toward WASM."* — and names the specific doubt: *"The 20% I held back is almost entirely about WASI Preview 2 specifically, not WASM in general."* That doubt was about an unstable interface. The event being waited on has now happened: WASI 0.2 and the component model stabilized in 2025. This is a tie-off whose condition came true with nobody assigned to notice.

**2. The substrate has what every WASM platform lacks, and lacks what all of them have.** Fermyon, Cloudflare Workers, Fastly Compute, Docker's Wasm support and the WASI registries have all solved execution — sandboxing, sub-millisecond cold start, capability grants. None has solved provenance or authority: who wrote this module, who authorized it to run *here*, and what can be proved about what it did afterward. That set is the ZeroPoint corpus. The asymmetry is the opportunity: runtimes without governance on one side, governance without a runtime story on the other.

**3. No new primitive is required, and that is the finding.** KEEL §IV.6 already defines a WASM module as *"content-addressed deterministic executable artifact loaded at runtime."* `ARTIFACT-LIBRARY-2026-05.md` already governs content-addressed signed artifacts. These are the same object described twice. An application, in this reading, is an artifact that happens to execute — admitted through the quarantine plane as an executable surface, under an operator-signed `delegation:admit:executable:<content_hash>`. The work is noticing the identity and building the one missing mechanism, not inventing a concept.

---

## The load-bearing structure

**The substrate's differentiated capability is not that an artifact ran. It is that a third party can verify what it produced without trusting whoever ran it.**

If a module is content-addressed, its inputs are chain-anchored receipts, and its execution is deterministic — no WASI, no ambient authority, fuel-bounded — then the computation is reproducible by anyone holding the same hashes. A receipt asserting *module H applied to inputs I yields output O* is checkable by re-execution rather than by trust in the executor. That composes directly with `REPRODUCIBILITY-CEREMONY-2026-07.md`, and it is the property no edge platform offers, because none of them needs it.

Everything else in this document is downstream of that sentence. Determinism is not hygiene; it is the thing being sold. The moment WASI enters a module's world the property is gone and the artifact becomes an ordinary serverless function.

---

## Two module classes

The corpus implies this split and should state it. KEEL §II.10 imposes a *"Deterministic execution constraint"* on the Officer trait. WASI is precisely the interface that grants nondeterminism — clock, randomness, filesystem, sockets. Both cannot govern the same class.

| | **Governed core** | **Adapter** |
|---|---|---|
| Examples | Officer, Cartographer, Regent, policy module, derivation component | Protocol adapter, inference backend, observation surface |
| WASI | None | Capability-scoped |
| Imports | ZP host functions only (§V.1–V.3) | ZP host functions plus WASI worlds |
| Determinism | Required | Not available |
| Replayable | Yes — this is the point | No |
| Receipt semantics | **Commit** — output is derived state | **Contact** — output is evidence, not truth |
| Failure of the boundary | A core that gains WASI silently stops being verifiable | An adapter treated as a core launders unverifiable input into derived state |

The bottom row maps onto P7. Adapters do contact; cores do commit. Stated that way, WASI is not on the critical path for the officer story at all — which is a considerable relief, since the corpus's own recorded doubt was WASI-specific.

---

## The core mapping

Classification: **Have** (mechanism exists in the corpus and in code) · **Specified** (in a document, no code) · **Missing** (neither) · **Refused** (structurally declined).

| Capability an app platform needs | ZeroPoint's answer | Status |
|---|---|---|
| Execute untrusted code in isolation | wasmtime 27.0 in `crates/zp-policy/src/wasm_runtime.rs` | **Have**, narrowly — feature-gated `policy-wasm`, off by default, one module class |
| Bound resource use | Fuel: 1,000,000 instructions per evaluation, replenished below 500,000; `wasm_threads(false)` | **Have**, partially — no `StoreLimits` memory cap, no epoch interruption |
| Mediate side effects through the gate | KEEL §II.8: *"they access side-effect primitives only through host-mediated interfaces that gate-check on the way out"* | **Specified** — `Instance::new(&mut store, &module, &[])` passes an empty imports list; guests have zero host functions |
| Identify a module | Blake3 content hash, per KEEL §VI canonicalization | **Specified** |
| Authorize a module to run here | `delegation:admit:executable:<content_hash>`, quarantine plane | **Specified** |
| Declare what a module may touch | `EXTENSION-SURFACE` TOML capability manifest | **Specified** — no loader; `crates/zp-server/src/extensions/` does not exist |
| Verify a module against its interface | KEEL §XIII.2 warm boot verifies trait conformance | **Specified** — hand-rolled against core wasm today; the component model would make it structural |
| Prove what a module did | Derivation receipt over `(module_hash, input_hash, output_hash)` | **Missing** — the differentiated capability, and it is unbuilt |
| Reputation of the publisher | `crates/zp-mesh/src/reputation.rs` — four signed categories, time-decayed, graded | **Have** |
| Distribute bytes | — | **Missing**, deliberately — see §Regulatory posture; belongs to a carrier |
| Catalogue, rank, curate | — | **Refused** |
| Namespace authority | Dissolved by content addressing | **Refused** |

---

## Why no app store

An app store is five things bundled. Four of them the substrate dissolves or refuses; the fifth is not a store.

**Naming.** Registries largely exist to answer *which `foo` is the real `foo`* — and then to police squatting and impersonation, which requires an authority that can revoke a name. Content addressing dissolves the problem: the hash is the name. Nothing to squat, nobody to adjudicate.

**Curation.** *"We vetted this, you may install it"* is transitive trust, which the corpus refuses explicitly. `PEER-TRUST-ANCHOR-2026-07.md` non-goals: *"Not a global reputation system"*, *"Not automatic trust bootstrap. New peers don't get default trust. Every peer trust anchor requires operator ceremony"*, *"Not a certificate authority model."*

**Reputation.** A store answers "is this safe" with review counts and a curator's judgment. The substrate answers it with signed evidence of how the publisher has actually behaved — `reputation.rs` scores across audit attestation, delegation chain, policy compliance and receipt exchange, time-decayed with a 30-day half-life. Better provenance, and already implemented.

**Rent and gatekeeping.** Neither is a goal, which removes the economic engine that makes stores exist in the first place.

**Availability** is the residue, and it is the one real need: somewhere to fetch bytes by hash. It gets conflated with *registry* constantly, and separating them is the move — availability wants a dumb pipe, not an authority, because content addressing means the source never has to be trusted, only reachable. That is `DECENTRALIZED-TRANSPORT-OPPORTUNITY-MAPPING-2026-07.md`'s carrier-never-a-gate boundary arrived at from the opposite direction, and two independent arguments landing on one boundary is the strongest signal available that the boundary is real.

**What a store would have provided and this does not:** finding something nobody you trust has heard of. The peer graph is empty on a cold start. This is not a new gap — `PEER-TRUST-ANCHOR-2026-07.md` already carries it as an open position, worded *"Bootstrapping semantics. First peer trust anchor for a fresh sovereign — how does the operator find any peer to trust?"* Same unresolved question, different object, which argues for solving it once.

---

## Regulatory posture

**Operator position, recorded 2026-07-27: the substrate does not host a catalogue, and the reason is not only architectural.** Hosting one would place ZeroPoint in a role that carries obligations the project has no interest in contending with.

The structural observation is that regulatory duties attach to *roles*, and the roles in question are precisely those the decomposition above already dissolves. Notice-and-action obligations presuppose an actor with the ability to take down. Curation duties presuppose a curator. Age-assurance requirements now landing at the app-store layer presuppose an app store — Clarke's FUTO talk (`docs/mindmaps/freenet-no-servers-clarke-2026-07.json`) cites California's operating-system-and-app-store verification mandate as an example, which demonstrates the obligation attaching to the *layer* rather than to any content. A substrate with no catalogue, no namespace it controls and no capacity to remove anything offers those duties nothing to fasten to.

The sharper point: intermediary protections generally turn on passivity. The more a service selects, ranks or blesses what it carries, the weaker its position as a neutral conduit. Curation is therefore not merely a P3 problem — it is the specific act that erodes the legal posture worth keeping. The architecture and the exposure fail together, which is unusual and worth exploiting: the design chosen on sovereignty grounds is also the one with the smallest surface in law.

This independently reinforces the availability split. If the substrate never hosts artifact bytes — if fetch-by-hash happens over a carrier the project does not operate — it is not a hosting service to begin with.

**The counterweight, stated deliberately rather than discovered later.** Refusing the store does not make the question disappear; it relocates it. A substrate that executes third-party components still raises questions — they attach to the operator running them rather than to a distributor. Under P9 that is coherent, since the operator signs and the operator bears. But it is a design choice, not an accident, and the operator is owed a clear statement that this is the deal.

**Recommended landing:** a standing non-goal in `CRYPTOGRAPHIC-SOVEREIGNTY-AND-LEGAL-PROCESS-2026-07.md` enumerating each refusal with the role it declines — no catalogue, no namespace authority, no hosting of artifact bytes, no capacity to revoke a third party's module — so it survives as a decision rather than as an instinct a later reader mistakes for an oversight. *This document does not make that edit; it recommends it.*

*Not legal advice. The specifics vary by jurisdiction and move quickly; this records the structural argument and the operator's position, and warrants professional review before the posture is stated publicly.*

---

## Verifiable outcomes (EA)

- **EA1** — A derivation receipt exists binding `(module_content_hash, input_content_hash, output_content_hash)`, operator-signed and chain-anchored.
- **EA2** — A second party holding only those three hashes and the module bytes can re-execute and reach a byte-identical output, without access to the first party's substrate.
- **EA3** — Every host function a guest can call is enumerable from the module's declared interface, and each call is gate-checked. No ambient capability reaches a guest.
- **EA4** — Governed cores import no WASI. This is checkable at load time by inspecting imports, and a core that imports a WASI interface fails admission rather than degrading silently.
- **EA5** — Resource bounds cover memory as well as instructions: a `StoreLimits` ceiling and epoch interruption alongside fuel.
- **EA6** — The substrate publishes no catalogue, hosts no artifact bytes, and exposes no interface by which it could revoke a third party's module. Checkable by the absence of the endpoints.
- **EA7** — Admission of any executable artifact traces to an operator-signed delegation naming the content hash.

---

## Minimum slice

**m0: make the mindmap renderer a deterministic component and emit a derivation receipt for one render.**

The renderer already claims the property in its own words — `tools/mindmap-mcp/README.md`: *"Renderer is deterministic and pure — same JSON in produces byte-identical HTML out. Convenient for content-addressed artifacts."* It needs no host functions, no filesystem, no clock and no network. It is a pure function from a content-addressed input to a content-addressed output, which is exactly the shape EA1 and EA2 describe.

The slice: compile it to a component, execute it under the existing `wasmtime` runtime with fuel and an empty import set, and emit `artifact:derived:<module>:<input>:<output>`. Then verify EA2 by re-running on a second machine from the hashes alone.

What makes this the right first slice is what it avoids. It introduces no new substrate concept. It requires none of the host-import work — the gap identified as §II.8's — because a pure function needs no imports. It exercises content addressing, deterministic execution, derivation receipts and reproducibility end to end. And its blast radius is that a mindmap fails to render, which compares favourably with making officers the first WASM citizens.

The host-import layer is the *second* slice, and it has its own natural minimum: wire exactly one import — `chain::read_recent` — from the wasmtime runtime through the existing `HostContext` trait in `crates/zp-host/src/context.rs`, gate-checked, emitting a receipt for the call. That module's own doc comment already anticipates it: *"When a WASM module is the caller, the host bindings will delegate to the same trait methods. The trait is the contract; the WASM ABI is an implementation of it."*

---

## Alternatives considered (tie-offs)

- **Make officers the first WASM citizens, per KEEL §IV.3.** *Disposition: deferred behind m0 and the host-import slice.* It is the corpus's stated end state and it depends on the entire §V.1 host-import surface, none of which exists. Doing it first means building the hardest dependency under the highest-stakes component. Reopens once one host import is proven end to end.
- **Adopt WASI now, for adapters.** *Disposition: deferred.* Nothing on either roadmap currently needs an adapter, `QUARANTINE-PLANE-2026-07.md` already carries the open position *"How do we handle capability declarations for WASM modules using experimental WASI features?"*, and the corpus's recorded doubt was WASI-specific. Reopens when a concrete adapter is wanted — most likely an inference backend.
- **Keep the JSON-over-linear-memory ABI rather than moving to WIT and components.** *Disposition: rejected, on timing.* Exactly one module type exists today, so the migration cost is at its historical minimum and rises monotonically with every module added. The component model also makes KEEL §XIII.2's trait-conformance check structural rather than a hand-written signature comparison.
- **Replace `execution-engine` with WASM.** *Disposition: rejected.* It sandboxes Python, Node and Shell through OS process isolation for arbitrary operator code; WASM governs substrate components the gate loads. Different concerns, and compiling arbitrary user scripts to WASM is not a near-term proposition. Reopens only if the two boundaries start enforcing the same policy in two places.
- **Host a catalogue.** *Disposition: refused* — see §Why no app store and §Regulatory posture. No reopen condition; this is a boundary, not a deferral.

---

## Open positions

- **A — Does KEEL §IV.3 get corrected or marked?** It states officers *"execute as WASM core against Layer A Officer trait interface"* in the present tense, in the Tier 1 document. In code they are native Rust trait objects in `crates/zp-officers/src/officer.rs`, with a different signature (`sweep`/`evaluate_entry` against §V.1's `wake`/`process`/`finding_shape`). *Resolution: an operator ruling — amend the claim to a stated destination, or add a specified-not-shipped marker. `docs/handoffs/wasm-rule-evaluation-2026-06.md` exists because this exact area has already been misread once.*
- **B — Which class does the Regent belong to?** §V.3's surface includes `inference::local/rally/cloud`, which is inherently nondeterministic. Under the two-class split the Regent cannot be a governed core in the same sense as an officer. *Resolution: either the Regent is an adapter whose emissions are contact rather than commit, or inference is host-mediated such that the nondeterminism sits outside the module boundary and enters as a signed input. The second is more consistent with §II.6's treatment of signing, and would be decided when the Regent's WASM boundary is first drawn.*
- **C — Where do derivation receipts sit relative to the artifact library?** `ARTIFACT-LIBRARY-2026-05.md` governs artifacts; EA1 proposes a receipt about the *relation between* three of them. *Resolution: either a new receipt family in the artifact library, or a specialization of an existing derivation edge in the ontology. Decided by whichever document lands m0.*
- **D — What is the cold-start answer for discovery?** The peer graph gives nothing for an artifact nobody you trust has seen, and this is the one function a catalogue would have served. *Resolution: shared with `PEER-TRUST-ANCHOR-2026-07.md`'s existing bootstrapping open position — solve once, for peers and artifacts together, or explicitly declare the substrate does not solve it.*
- **E — Does `wasmtime`'s dependency weight change?** `DEPENDENCY-POSTURE.md` catalogues it for policy evaluation, which is a narrow, feature-gated use. If executable artifacts become a first-class surface, wasmtime moves from optional to load-bearing, and the Bytecode Alliance's governance — including Akamai's December 2025 acquisition of Fermyon, a major contributor — becomes worth a posture entry. *Resolution: a `DEPENDENCY-POSTURE` revision at the point the feature gate comes off by default.*

---

## What is specified vs. what is shipped

Per A11, and emphatically, because this subject has already produced one documented over-read:

- **Shipped and verified by direct read:** `wasmtime` 27.0 in `crates/zp-policy/src/wasm_runtime.rs`; module loading from `.wasm`/`.wat`; a JSON-over-linear-memory ABI requiring `name_ptr`/`name_len`/`alloc`/`evaluate`/`evaluate_len` exports plus `memory`; fuel metering at 1,000,000 instructions with replenishment below 500,000; `wasm_threads(false)`; `PolicyModuleRegistry` with content-hash keying and `Active`/`Disabled`/`Error` status, wired into `zp-cli` and `zp-server`; `.wat` test fixtures covering allow, block, null decision, fuel replenishment across 50 evaluations, module reset and missing-export rejection.
- **Shipped but off:** the `policy-wasm` feature is `default = []` in `zp-policy`, and neither `zp-cli` nor `zp-server` includes it in their own defaults. It ships only under an explicit feature selection.
- **Specified, not shipped:** every host import in KEEL §V.1–V.3; the §II.8 gate-checked side-effect mediation; the `EXTENSION-SURFACE` capability manifest, loader and network-egress mediation (`crates/zp-server/src/extensions/` does not exist); trait-conformance verification at warm boot; officers as WASM cores.
- **Absent entirely:** `wasmtime-wasi` is not a dependency of any crate in the workspace. WASI is discussed extensively in `docs/` and appears nowhere in `crates/`.
- **Absent by omission rather than decision:** no `StoreLimits` or `ResourceLimiter` is configured, so wasmtime's default memory ceiling applies unmodified; epoch interruption is never enabled.
- **A doc citing a path that does not exist:** `AGENT-TOOL-CONTRACT-2026-06.md` §7 describes tools executing *"inside Wasmtime with declared capability schemas (`src/tools/wasm/capabilities.rs`)"*. No such path is present. Its reference implementation was IronClaw, which was disconnected from the repo on 2026-07-27 (`docs/handoffs/ironclaw-tieoff-2026-07-27.md`).
- **Outside the canonical corpus:** `wasm-modules/` contains compiled `wasm-bindgen` browser artifacts unrelated to this architecture, and is not indexed by `CANONICAL-CORPUS-INDEX-2026-07.md`. It should not be read as evidence of a server-side WASM capability.

---

## Non-goals

- **Not an app store, a catalogue, a registry, or a namespace authority.** A boundary, not a deferral. See §Why no app store and §Regulatory posture.
- **Not artifact hosting.** The substrate does not serve bytes. Availability belongs to a carrier the project does not operate.
- **Not a claim that officers should become WASM cores soon.** This document argues the opposite ordering — prove the mechanism where the stakes are lowest.
- **Not a WASI adoption proposal.** Governed cores must not have it; adapters are deferred until one is actually wanted.
- **Not a replacement for `execution-engine`.** Two sandboxes, two purposes, declared deliberately rather than left to drift.
- **Not a performance argument.** Sub-millisecond cold start is the video's headline and is close to irrelevant here. The property being purchased is verifiability, not speed.
