# Software Integrity Attestation — July 2026

**Document type:** Design note. Establishes a general substrate primitive: **software integrity attestation for runtime claims about behavior.** The pattern surfaced during the community-surface design session as "non-recording attestation" for locked-door sessions, but generalizes beyond that single application. This document specifies the pattern independently of any specific application and then lists the applications that inherit from it.

**Status:** Design note. Ready for iteration; open decisions marked.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-05.

---

## Part I — The Problem

Every existing decentralized system that makes runtime behavioral claims ("this software does not record," "this software does not exfiltrate," "this software follows the constitutional rules") ends up relying on some form of "trust us." Zoom promises to notify. Signal's disappearing messages depend on the client honoring the setting. Legal frameworks provide recourse but not prevention. Policy statements are policy statements.

In a substrate where signing is gravity and constitutional rules are conservation laws, "trust us that we're behaving as claimed" is out of character. Every other guarantee ZP makes is structural — chain integrity is cryptographic, delegation narrowing is invariant, capability grants are receipts. Runtime behavioral claims should be structural too.

The right move is to make behavioral claims *structurally attested* rather than politely promised. This is what the software integrity attestation pattern does.

---

## Part II — The Attestation Stack

Software integrity attestation is a stack of composable defenses, no single layer sufficient alone.

### 2.1 Build attestation

Each ZP node runs a specific build with a chain-anchored release receipt. The Foundation — or reproducible-build infrastructure independent of the Foundation — signs the release with a receipt declaring:

- **Build hash** (the cryptographic identifier of the built binary)
- **Source hash** (the cryptographic identifier of the source code that produced this build)
- **Declared capabilities** (what this build does; what it does NOT do)
- **Signature** from the release-signing key
- **Provenance chain** back to the release-signing key's authority

A node running this build produces attestations tied to the build's hash. Peers verify: the attestation signature is valid, the build hash matches a known release receipt, no known-modified forks. Modified builds that deviate from released behavior cannot produce valid attestations because their build hash won't match any signed release receipt.

The chain-of-trust bottoms out at whichever party the community trusts for build signing. This is typically the Foundation for the reference builds; other parties can produce their own release chains for their own forks, and communities decide which release chains they trust.

### 2.2 Runtime attestation

The node attests, at the moment of a specific action or session join:

- **What software is currently running** — build hash, module list, loaded plugins
- **What processes are active** — no unauthorized processes running that could interfere
- **What claims are being made** — the specific behavioral commitment for this context
- **A signature** from the node's identity key, binding all of the above

Peers verify against the build's declared capabilities. A node claiming "no recording" that runs a build declaring recording modules fails verification. The runtime attestation is a checkpoint claim: "at this moment, my running software is exactly this build with these declared capabilities."

### 2.3 Hardware attestation (where available)

TPM (Windows, Linux, some Android), Secure Enclave (macOS, iOS), StrongBox (Android with hardware backing), or dedicated attestation modules can produce cryptographically strong attestations about the running OS and software. Where the platform supports it, hardware attestation is stronger than software attestation because it's harder to fake at the software level.

Not all devices have hardware attestation. The pattern gracefully degrades: sessions can require hardware attestation for high-security contexts and accept software attestation for casual contexts.

### 2.4 Reputation stake

The attestation is signed by the operator's identity. The operator's reputation stake is on the line: if the attestation is proven false — the operator is caught doing what they attested not to do — reputation degradation is severe and chain-visible.

This provides the game-theoretic anchor. Even if all technical layers can be evaded by a sophisticated attacker, the reputational cost of being caught scales with the ecosystem's ability to observe the violation. In a well-functioning community, sophisticated evasion is not worth the reputation cost.

### 2.5 Continuous re-attestation

During long-lived commitments (sessions, ongoing capability grants, extended real-time interactions), participants' nodes emit periodic re-attestations. Cadence is context-configurable — every five minutes for high-security sessions, less frequent for casual contexts.

A node that stops re-attesting is treated as suspect. The session convener or capability grantor can eject the participant or revoke the grant. This handles the case where attestation was true at commitment time but became false later.

### 2.6 Composition of the layers

Each layer is independently defeatable by a sufficiently capable adversary:

- Build attestation can be defeated by compromising the build-signing key
- Runtime attestation can be defeated by modifying the running software after signing
- Hardware attestation can be defeated by hardware compromise
- Reputation stake can be defeated by not caring about reputation
- Continuous re-attestation can be defeated by faking each attestation continuously

Combined, they're substantially harder to defeat. An adversary needs to either compromise the entire attestation stack simultaneously or accept that their evasion will eventually be detected and consequential.

---

## Part III — What Perfect Enforcement Can and Can't Do

Explicit about what the pattern claims:

### 3.1 What it can do

- **Prevent silent behavioral violations by ZP-native software** — modified builds cannot attest as unmodified builds without breaking the chain-of-trust to release receipts.
- **Make TPM-attested violations near-impossible without hardware compromise** — hardware attestation stack requires physical compromise, which is expensive.
- **Provide chain-visible evidence for consequences after violations** — every attestation is a chain receipt; every violation, once detected, is provable and attributable.
- **Impose meaningful reputation and constitutional costs on caught violations** — the reputation stake ensures caught violations have consequences.

### 3.2 What it cannot do

- **Prevent out-of-band behaviors** — an operator can point a separate device at their screen to record; the ZP node's attestation only claims what the ZP node itself is doing, not what physical peripherals are doing.
- **Prevent code execution as the operator** — malware running with operator privileges can wait for authentication and act as the operator; storage-layer attestation doesn't solve this. Hardware attestation partially addresses; not universally.
- **Defeat sophisticated hardware-level compromise** — a well-resourced adversary with hardware attack capability can defeat some or all of the attestation stack.
- **Guarantee that all violations will be detected** — some violations may only be detected after significant harm has occurred; the pattern provides accountability for detected violations, not prophylactic prevention of all violations.

The honest framing: attestation raises the cost of surreptitious violation enough that most attempts are deterred, and any successful attempt is attributable and consequential. It does not claim perfect prevention.

---

## Part IV — Chain-of-Trust for Build Attestation

The chain-of-trust anchoring build attestation is worth detailing because it's the load-bearing structural component.

### 4.1 The release chain

The Foundation (or any other release-signing authority) maintains a release chain — a sequence of chain-anchored receipts, one per released build. Each release receipt declares:

- Build hash (Blake3 of the built binary)
- Source repository commit hash
- Build environment fingerprint (compiler version, dependencies, target platform)
- Declared capabilities (structured description of what this build does and does not do)
- Backward-incompatible-behavior flags (if any)
- Signature from the release-signing key
- Reference to the previous release receipt (forming the release chain)

### 4.2 Release-signing key management

The release-signing key must be handled with care:

- **Ceremonial multi-party control** — the release-signing key is not held by any single individual. Signing releases requires ceremony involving multiple parties.
- **Hardware-backed storage** — the private key material lives in hardware security modules or hardware wallets.
- **Chain-anchored key rotation** — when the release-signing key is rotated, the transition is a chain-anchored receipt signed by both the old and new keys.
- **Verification against multiple sources** — nodes verify release signatures against not just the release-signing key but also against community-attested reproducibility. If multiple independent parties have reproduced the build and confirmed the hash, that's stronger evidence than the release-signing key alone.

### 4.3 Reproducible builds

The build attestation is only meaningful if builds are reproducible — anyone with the source code can build the binary and independently verify the hash matches the release receipt. Reproducible builds require:

- Deterministic build tooling
- Fixed dependency versions with cryptographic hashes
- Time-independent build outputs (no embedded timestamps)
- Fixed target platform fingerprints

Reproducibility is a substantial engineering commitment. It is worth it because it eliminates the trust dependency on any single build-signing party — any observer can verify.

### 4.4 Community-maintained forks

Forks can produce their own release receipts under their own release-signing keys. Communities decide which forks they accept for participation in their spaces. A non-Foundation-blessed fork can still be trusted if the community has independently verified it and its release chain.

This is important: build attestation does not privilege the Foundation. It privileges any release chain the community accepts.

---

## Part V — Applications of the Pattern

The software integrity attestation pattern applies to many runtime behavioral claims. Non-recording was the first application to surface but is not the only one.

### 5.1 Non-recording attestation

**Context:** Locked-door sessions, private conversations, ephemeral communications.

**Claim:** "This ZP node is not recording session content. No output-capture modules are loaded. No unauthorized processes are active."

**Attestation:** Build attestation (this build has no recording modules), runtime attestation (no capture processes running), hardware attestation where available (TPM confirms OS state), reputation stake (the operator's reputation is on the line), continuous re-attestation (renewed every 5 minutes during the session).

**Exceptions:** Explicit opt-in for legitimate recording — sessions declared as recorded, or specific participants granted recording capability via mandate.

### 5.2 No-exfiltration attestation

**Context:** Sensitive content shared to a specific community; capability-granted access to specific chain segments; commons emissions.

**Claim:** "This ZP node is not exfiltrating this content to external servers or unauthorized parties. Content received under mandate stays within the mandate's scope."

**Attestation:** Same stack as non-recording, applied to different declared capabilities. The build attests to not containing exfiltration modules; runtime attests to no unauthorized network connections; hardware attests to OS state.

**Applications:** Research query mandates (data queried under mandate stays within the mandate's declared analysis); community content (shared to a bounded space, not re-shared out); commons priors (received priors used locally, not aggregated and re-published without attribution).

### 5.3 No-unauthorized-analysis attestation

**Context:** Sensitive content that the operator does not want subjected to specific kinds of analysis. Examples: session content that should not be used for ML training, personal chain content that should not be behaviorally profiled.

**Claim:** "This ZP node is not running unauthorized ML analysis, behavioral profiling, or content processing on data received in this context."

**Attestation:** Build attests to declared analysis capabilities; runtime attests to no unauthorized analysis processes; hardware attests to system state.

**Applications:** Bounded-space content protection, research participant data protection, ephemeral communication content protection.

### 5.4 Constitutional rule integrity attestation

**Context:** Every ZP action passes through the constitutional rules. If a node is running modified constitutional rules, its actions cannot be trusted.

**Claim:** "This ZP node is running the constitutional rules signed to its chain, not a modified version. HarmPrincipleRule and SovereigntyRule evaluate on every action."

**Attestation:** Build attests to unmodified constitutional rule implementation; runtime attests to constitutional rules being present and evaluating; hardware attests to the code executing being the expected code.

**Application:** Every substrate action. Constitutional rule integrity is arguably the most load-bearing attestation because it's the foundation of every other guarantee.

### 5.5 Differential privacy budget accounting attestation

**Context:** Research mandates use DP budgets to bound information extraction. If a querier's node is under-counting budget consumption, the DP guarantee is compromised.

**Claim:** "This ZP node correctly accounts DP budget consumption per the mandate's specified DP mechanism."

**Attestation:** Build attests to correct DP accounting implementation; runtime attests to the accounting state; queries include chain-anchored receipts of budget consumption that receivers can verify.

**Application:** Research participation, mandate-scoped queries against operator chains.

### 5.6 Non-recording generalizes to "no-persistence-beyond-declared"

The non-recording attestation is a specific case of "no persistence of session content beyond declared retention." Persistent sessions have declared retention (encrypted to participant chains); ephemeral sessions have declared zero retention. The attestation is that no undeclared persistence is happening — no out-of-band recording, no unauthorized backup, no hidden logging.

### 5.7 Drafter checkpoint integrity attestation

**Context:** Speculative-decoding drafters (per MODEL-DOSSIER-2026-07's operational serialization) are lightweight models that participate in every inference call once activated. Their integrity is a runtime behavioral claim in exactly the same class as the applications above.

**Claim:** "The drafter running against this target model is the specific checkpoint the operator ratified — same weights hash, same training provenance, same byte-identical parity attestation as when adopted."

**Attestation:** Build attests to the drafter's checkpoint hash and training-corpus hash (per the training-run receipt on chain); runtime attests to which drafter checkpoint is currently loaded in the inference server; hardware attests to inference-server state where available; continuous re-attestation via the acceleration-ablation shadow scenario (per SHADOW-EVALUATION-PRIMITIVE Context 1) periodically re-establishes the byte-identical parity claim on the substrate's actual workloads.

**Applications:** Regent's cognitive path (a swapped drafter under a stable name changes the operational characterization of a model without the operator's knowledge — same failure class as INFERENCE-ROUTING-DISCIPLINE's silent-version-drift, one layer down). Any cognitive work that dispatches through an accelerated inference path inherits the drafter's integrity claim as part of its chain evidence.

**Composition:** The `drafter.checkpoint_hash`, `drafter.training_run_receipt`, and `drafter.byte_identical_parity_receipt` fields on MODEL-DOSSIER's drafter sub-record are the specific fields this attestation binds to. Under this pattern, MODEL-DOSSIER's characterization ceremony IS a build attestation for the drafter, and OBSERVATION-PLANE's `observation:inference:drafter_acceptance` telemetry IS the runtime attestation surface.

### 5.8 The pattern extends further

Each of these applications shares the same underlying structure:

1. A specific behavioral claim relevant to a context
2. Build-time declaration of what the software does and doesn't do
3. Runtime attestation checkpoint tied to the specific action or session
4. Optional hardware attestation for high-security contexts
5. Reputation stake and constitutional binding
6. Continuous re-attestation for long-lived commitments

Future runtime behavioral claims can inherit this stack directly. The primitive is generalizable.

---

## Part VI — Composition with the Substrate

### 6.1 Attestations as chain receipts

Every attestation is a chain receipt: signed, hash-linked, verifiable, immutable. Attestations join the operator's chain like any other action. This gives:

- **Provenance for every claim.** Any attestation can be traced back to the operator who made it.
- **Consequences for false claims.** If an attestation is later shown to be false, the receipt is chain-visible evidence of the operator's commitment. Reputation and constitutional consequences flow.
- **Cross-operator verification.** Peers can verify attestations without trusting any central party.

### 6.2 Peer discovery for attestation verification

Attestations often need to be verified by peers before an interaction proceeds. Peer discovery (per `PEER-DISCOVERY-AS-OUTREACH-2026-07.md`) provides the transport. Session convening includes an attestation check: peers verify each other's attestations before the session opens. Mandate grants include attestation requirements.

### 6.3 The Regent as attestation surface

The operator's Regent handles the presentation of attestations:

- **On the emitting side:** the Regent shows the operator what they're about to attest to. "You're about to attest that your device is not recording during this session. Verify?"
- **On the receiving side:** the Regent shows the operator what attestations peers have made. "Ken has attested no-recording for this session. His attestation stack includes hardware attestation from his device. Trust level: high."
- **On the violation side:** if the Regent detects that an attestation is likely false, it surfaces the concern.

### 6.4 Reputation dynamics for attestation quality

Operators who make many successful attestations without violation accumulate reputation for attestation reliability. Operators who violate attestations (once detected) lose reputation catastrophically. The reputation-of-attestation-reliability composes with other reputation dimensions.

---

## Part VII — Adversarial Dynamics

### 7.1 Malicious build claiming to be Foundation build

**Attack:** Attacker distributes a modified ZP client that attests as if it were a stock Foundation build.

**Defense:** The attestation includes the build hash. The build hash must match a hash from a known Foundation release receipt. Modified builds have different hashes, so their attestations fail verification.

**Escalation:** Attacker attempts to compromise the Foundation's release-signing key.

**Defense:** Multi-party release signing ceremony; hardware-backed key storage; chain-anchored key rotation. Compromising the release-signing key requires compromising multiple parties simultaneously.

### 7.2 Compromised TPM / secure enclave

**Attack:** Sophisticated adversary with hardware attack capability compromises the TPM or Secure Enclave, forging hardware attestations.

**Defense:** Multi-layer attestation. Even if hardware attestation is compromised, software attestation, reputation stake, and continuous re-attestation still apply.

**Practical reality:** Hardware attacks are expensive and detectable. This threat applies to nation-state adversaries; not to typical operators.

### 7.3 Legitimate build with runtime injection

**Attack:** Attacker installs modified software post-boot that injects behavior into an otherwise-legitimate build. The build attestation is technically valid, but runtime behavior differs.

**Defense:** Runtime attestation catches this if the injection changes what the software claims to be running. Continuous re-attestation catches drift over time. Hardware attestation (where present) catches OS-level modifications.

**Limit:** Very sophisticated attacks that inject behavior without changing measurable runtime state are hard to catch. This is a real limit.

### 7.4 Attestation staleness

**Attack:** Attestation was true at commitment time, but the software or environment changed since.

**Defense:** Continuous re-attestation with configurable cadence. Nodes that stop re-attesting are ejected from ongoing commitments.

### 7.5 Out-of-band violation

**Attack:** Operator uses a separate device to record what the attesting ZP node is not recording. Or uses a separate device to exfiltrate content that the attesting ZP node is not exfiltrating.

**Defense:** No structural defense — the attestation is about what the ZP node itself is doing, not about what physical peripherals are doing. Handled by constitutional rules (HarmPrincipleRule interpreted to include unauthorized recording where consent hasn't been obtained) and reputation dynamics (violators lose standing catastrophically once discovered).

### 7.6 Session hijacking

**Attack:** Attacker takes over a session and attempts to lie about what's happening in it.

**Defense:** Session authority is capability-scoped and chain-anchored. Attestations from unauthorized parties fail verification. Convener authority cannot be transferred except by explicit chain-anchored transfer receipt.

---

## Part VIII — Open Design Decisions

1. **Attestation format.** Concrete wire format for attestations: fields, signature scheme, encoding.

2. **Re-attestation cadence defaults.** How often should continuous re-attestation happen? Depends on context; needs sensible defaults.

3. **Hardware attestation abstraction.** How the substrate abstracts across TPM, Secure Enclave, StrongBox, and other hardware attestation surfaces. Different platforms have different capabilities.

4. **Reproducible-build tooling.** Which reproducible-build infrastructure ZP adopts. Existing options (Nix, Bazel, Debian's rebootstrapping work) are candidates.

5. **Community-fork acceptance mechanics.** How communities declare which release chains they accept for participation in their spaces. Discovery mechanism for release chains.

6. **Violation reporting protocol.** When a violation is detected (attestation shown to be false), what's the receipt format for reporting it? How does the ecosystem propagate the report? What's the appeal mechanism for disputed reports?

7. **Attestation privacy.** Attestations carry information about what software the operator is running. Is that information sensitive? Should attestations reveal build-hash only, or also declared-capabilities detail? Trade-off between verification transparency and operator privacy.

---

## Part IX — Companion Documents

- `docs/ARCHITECTURE-2026-07.md` — canonical architecture record; principle 6 (a tool is intent, crystallized) is the foundational commitment that structural attestation operationalizes.
- `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md` — attestations are verified via peer discovery mechanism.
- `docs/design/ENCRYPTED-STORAGE-ARCHITECTURE-2026-07.md` — attestations of storage behavior (encryption compliance, no-unauthorized-exfiltration) are applications of this pattern.
- `docs/design/REGENT-COMPARTMENTALIZATION-2026-07.md` — the Regent's role in presenting attestations to the operator.
- `docs/design/COMMUNITY-SURFACE-ARCHITECTURE-2026-07.md` — locked-door sessions, non-recording contexts, and other applications from the community surface.
- `docs/PERSONALITY-ADAPTATION-VALIDATION-PROTOCOL-2026-07.md` — DP budget accounting attestation applies here.

---

*Runtime behavioral claims are structural, not policy. Every claim of the form "this software does X" or "does not do Y" is anchored in build attestation, runtime attestation, hardware attestation where available, reputation stake, and continuous re-attestation. The pattern generalizes: non-recording is the first application, but no-exfiltration, no-unauthorized-analysis, constitutional-rule integrity, DP budget accounting, and every future behavioral claim inherit the same stack.*
