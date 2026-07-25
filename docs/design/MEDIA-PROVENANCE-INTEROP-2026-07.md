# Media Provenance — Interoperability Composition Patterns

**Document type:** Tier 2 canonical elaboration — companion to `MEDIA-PROVENANCE-2026-07.md`.
**Elaborates:** KEEL §II.5 (sovereign identity), §II.8 (chain-anchored evidence), §III.19 (detectability), §III.22 (evidence-based ceremony), Part VII (peer verification). Scope: how ZP's operator-anchored media provenance composes with the existing mainstream C2PA ecosystem (Adobe tools, AWS pipelines, camera-vendor implementations) without ceding trust root.
**Date:** 2026-07-18. Motivated by:
- Nikon's C2PA infrastructure vulnerability (September 2025) causing mass certificate revocation across all Nikon C2PA-enabled cameras — a real-world instance of vendor-anchored trust failure.
- Reference architecture analysis (SoftwareSeni + AWS media provenance guidance) showing the mainstream enterprise C2PA pattern: cloud KMS + ES256 + Lambda/Fargate + custom-signer hooks.
- Recognition that the ZP substrate's Ed25519-native + operator-held-key posture creates real interoperability questions with the existing tool ecosystem.

**Author:** Ken Romero, with synthesis assistance from Claude.
**Status:** Living discipline. Interoperability decisions are architectural; each has trade-offs that operators (and the substrate at design time) resolve deliberately. This spec surfaces the decision space so choices are made explicitly rather than discovered at implementation time.

---

## Formal lens declaration

Per `LENS-DISCIPLINE-2026-07.md`, this document declares the following lens as its first-class canonical form. The interoperability analysis below elaborates the declaration. Companion to `MEDIA-PROVENANCE-2026-07.md` (which declares the parent `media_provenance` lens — that one covers the ZP-model substrate primitive; this one covers the ecosystem-composition surface).

- **`lens_id`**: `media_provenance_interop`
- **`focus`**: how operator-anchored ZP media provenance composes with the mainstream C2PA ecosystem (Adobe tools, AWS pipelines, camera-vendor implementations) without ceding trust root
- **`dimensions`**: cryptographic algorithm mismatch (Ed25519 ↔ ES256), trust root mismatch (operator-held ↔ cloud-hosted KMS), signing-tier scaling (short-image vs long-video), certificate lifecycle (static Secrets-Manager ↔ Genesis rotation), signer-hook interoperability (Adobe / c2patool custom-signer endpoints), blast-radius composition (per-vendor ↔ per-operator), verifier-side backward compatibility
- **`keyword_composition`**: [C2PA, interop, ES256, ECDSA, ECDSA-SHA-256, Ed25519, KMS, cloud signing, custom signer, c2patool, Adobe verifier, AWS MediaConvert, certificate lifecycle, certificate revocation, PKI, Nikon revocation, vendor certificate, hybrid signing, signature translation, algorithm agility, cert chain, X.509, JWS, signer hook, verifier compatibility, capture-tier scaling, Lambda, Fargate]
- **`transformation_question`**: *"how does this substrate primitive maintain per-operator sovereign trust root while remaining verifiable to mainstream C2PA tooling that expects vendor-anchored ES256?"*
- **`cross_references`**: `MEDIA-PROVENANCE-2026-07.md` (parent lens; substrate-primitive layer), `KEEL-2026-07.md` §II.5 (sovereign identity), §II.8 (chain-anchored evidence), §III.19 (detectability), §III.22 (evidence-based ceremony), Part VII (peer verification), `PEER-TRUST-ANCHOR-2026-07.md`, `GENESIS-ROTATION-CEREMONY-2026-07.md`, `VAULT-KEY-SOVEREIGNTY-COMPOSITION-2026-07.md`, `AI-LANDSCAPE-SIGNAL-2026-07.md`

When chain-anchored as a `lens:declared:media_provenance_interop` receipt, invocation semantics follow the lens discipline: any work context matching the keyword composition triggers a `lens:applied:media_provenance_interop:<invocation_id>` receipt. Composes-with `media_provenance` via keyword overlap: `lens:composed:media_provenance:media_provenance_interop` is the structural relationship, emitted when both lenses fire on the same work context. Silent-media-provenance-interop-lens over a long observer window is a signal that substrate work has stopped attending to ecosystem-composition constraints — either the constraints stabilized (ok) or the substrate drifted toward pure-ZP posture without maintaining verifier compatibility (worth surfacing). Directional: outside-in (external ecosystem infrastructure → substrate composition patterns).

---

## Part I — What this addresses

`MEDIA-PROVENANCE-2026-07.md` names the ZP model: media provenance receipts are chain-anchored, signed under operator Genesis, verifiable via peer verification. It does not exhaustively address how ZP composes with — or diverges from — the existing C2PA ecosystem's practical implementation patterns.

**Concrete interoperability questions this document resolves:**

1. Cryptographic algorithm mismatch: ZP is Ed25519-native; mainstream C2PA tooling (AWS MediaConvert, Adobe verifiers) expects ES256 (ECDSA-SHA-256).
2. Trust root mismatch: mainstream C2PA infrastructure assumes cloud-hosted signing (KMS-backed); ZP assumes substrate-hosted signing (operator-held key).
3. Signing-tier scaling: mainstream splits short (image) vs long (video) tasks across Lambda/Fargate; ZP needs its own analogous split.
4. Certificate lifecycle: mainstream treats certs as static Secrets-Manager-stored artifacts; ZP has active Genesis rotation via ceremony.
5. Signer-hook interoperability: mainstream tools (Adobe, c2patool) accept "custom signer" endpoints — a natural wedge for substrate composition.

**Blast-radius framing** (empirical validation from Nikon incident):

The Nikon September 2025 incident revoked certificates across the entire Nikon C2PA fleet. Sony, Leica, Canon fleets were unaffected — the blast radius was contained to Nikon's PKI. This proves C2PA's federated-vendor model is already partially resilient: **vendor incidents are per-vendor, not ecosystem-wide.** ZP's "each operator holds their own signing root" architectural move takes the resilience domain one step further: per-operator, not per-vendor. Same architectural progression, further along. This document names it as a first-class property of the substrate's media provenance discipline.

---

## Part II — Algorithm compatibility (ES256 vs Ed25519)

The mainstream C2PA verifier ecosystem — including AWS MediaConvert (which specifically requires `ECDSA_SHA_256` KMS keys), Adobe Content Credentials, and most C2PA validator libraries — assumes ES256 signing. The C2PA specification permits Ed25519, but adoption of Ed25519-signed manifests is uneven; Ed25519 manifests validate correctly against C2PA reference libraries but may fail with vendor-specific implementations that hard-code ES256 support.

ZP is Ed25519-native across the entire key hierarchy: Genesis, operator, agent keys, delegation signatures. This is a deliberate architectural choice for cryptographic hygiene (Ed25519's fixed parameters remove some ECDSA implementation pitfalls) and small-signature-size properties.

**Three approaches to reconcile:**

### Approach A — ES256 as supplementary derived key

Extend the operator key hierarchy with an ES256 signing key derived from Genesis via HKDF or similar KDF with a domain-separation label. The Genesis secret remains the singular sovereign root; the ES256 key is one of the derivations, alongside audit-signer, vault key, delegation-signing key.

**Pros:**
- Full interoperability with existing C2PA verifier tooling.
- ES256 media provenance receipts validate directly in Adobe, browser plugins, camera-vendor tools.
- Singular-sovereign-root discipline preserved: one Genesis, all keys derived.

**Cons:**
- Substrate carries a second signing algorithm implementation surface.
- Media provenance receipts signed with ES256 use a different key than the operator's Ed25519 chain-signing key. Verifiers need to know which key type applies to which receipt class.
- ECDSA implementation carries more subtle failure modes than Ed25519 (nonce reuse, timing attacks). Requires a well-audited ES256 implementation.

### Approach B — Ed25519-only, accept limited ecosystem interop

Sign C2PA manifests with the operator's existing Ed25519 keys. Manifests validate against C2PA spec conformance but may not verify in vendor-specific tools that hard-code ES256.

**Pros:**
- Minimal implementation surface.
- Cryptographic hygiene preserved uniformly.
- Substrate remains coherent (one algorithm, one key hierarchy).

**Cons:**
- Broken interoperability with Adobe Content Credentials, AWS MediaConvert, most existing verifiers.
- Substrate produces media provenance that only ZP-aware verifiers accept.
- Ecosystem exclusion is a soft form of sovereignty tax on the operator.

### Approach C — Dual-sign per manifest

Every media provenance receipt carries BOTH an Ed25519 signature (over the substrate-native manifest) AND an ES256 signature (over the C2PA-standard manifest). Both signatures derive from Genesis-hierarchy keys (per Approach A's ES256 derivation).

**Pros:**
- Maximum interoperability. Existing C2PA tools verify the ES256 signature; ZP-aware verifiers verify the Ed25519 signature or both.
- Cryptographic hygiene preserved (Ed25519 remains the substrate-native path).
- Failure of one algorithm's ecosystem doesn't compromise the other.

**Cons:**
- Fatter manifests (both signatures + certificate chains).
- Two signing operations per capture (compute cost).
- Two verification paths that must remain consistent (drift is possible).

**Recommendation at spec entry time: Approach C for the ZP Camera App and any substrate-mediated media capture. Approach B for internal-only substrate-to-substrate media exchange where the operator is confident only ZP-aware verifiers will see the receipt. Approach A is a viable middle ground but does not preserve substrate-native Ed25519 verification for interop-visible receipts.**

Codified in ZP Camera App spec: dual-sign by default; operator can opt into Ed25519-only mode via chain-anchored preference receipt for sovereignty-consistency-over-interop cases.

---

## Part III — Custom-signer wedge (interoperability strategy)

Mainstream C2PA tooling (Adobe, `c2patool`, AWS solutions) supports a **custom signer** hook: the C2PA library computes the claim bytes and passes them to an external endpoint for signing, then receives the signature back to attach to the manifest. Originally intended for HSMs and cloud KMS integration; the same interface accommodates substrate-hosted signing.

**The wedge:** ZP substrate exposes a local signing endpoint (Unix socket, localhost HTTP, or IPC) that implements the C2PA custom-signer contract. Adobe Photoshop, Premiere, Lightroom Classic (or any C2PA-enabled editing tool) can be configured to sign against the substrate's endpoint instead of AWS KMS. The signing key never leaves the substrate; the tool sees only the signature.

**Composition properties:**

- **Backward compatibility.** Substrate composes with the existing tool ecosystem without requiring a full replacement stack. Operators can continue using Adobe/Premiere/etc. as their editing environment.
- **Chain-anchored evidence per signing.** Every custom-signer invocation lands a `media:signing_request:accepted` or `:refused` receipt with the requesting tool identity, claim hash, and operator delegation used.
- **Gate-enforced.** The substrate's authority gate mediates signing requests. Not every process can request signing; the tool must have an operator-delegated capability for media provenance signing (per `capability:media:sign` class).
- **Audit trail is the substrate's chain, not the vendor's telemetry.** The operator sees who signed what, when, using which key, in their own chain evidence — not in Adobe's cloud logs.

**Concrete endpoint shape** (implementation-level, informative):

```
POST /api/v1/media/sign
Content-Type: application/json
X-ZP-Delegation: <delegation-receipt-id>

{
  "algorithm": "ES256" | "Ed25519",
  "claim_bytes": "<base64>",
  "requesting_tool": "adobe.photoshop.25.1.0",
  "media_type": "image/jpeg" | "video/mp4" | ...,
  "manifest_url": "urn:...",
}

Response:
{
  "signature": "<base64>",
  "certificate_chain": ["<pem>", ...],
  "chain_receipt_id": "<receipt-id-of-signing-event>",
}
```

The substrate emits `media:signing_request:{accepted,refused}` per invocation. The response's `chain_receipt_id` is a first-class handle for post-hoc verification.

**Composition with QUARANTINE-PLANE-2026-07.md:** the custom-signer endpoint is a substrate admission surface for external tool signing requests. Same admission ceremony as any other incoming request: operator-declared delegation, chain-anchored evidence, gate enforcement.

---

## Part IV — Signing-tier scaling (substrate-local vs rally)

The mainstream AWS pattern splits C2PA signing by task duration: Lambda for short (image) signing, Fargate for long (video) signing. This is a real architectural pattern responding to real resource asymmetry: image signing is milliseconds and RAM-cheap; video signing is minutes-to-hours and RAM-hungry.

ZP's substrate has the same asymmetry and the same natural split:

**Substrate-local signing (analog to Lambda):** image capture, short audio clips, small documents. Runs on whatever device the operator is currently active on. Latency milliseconds; signing key already loaded per singular-sovereign-root ceremony at boot. No rally needed.

**Rallied signing (analog to Fargate):** video capture at meaningful duration, long audio sessions, large document sets. Runs on a workstation-class node in the operator's fleet per `MULTI-DEVICE-OPERATION-2026-07.md` and the rally primitive (per KEEL Decision C). Rally is Genesis-authenticated end-to-end; results return signed.

**Bright line for tier selection:** operator-declared per media class in the substrate's media-provenance configuration. Default: images sign local, video >30 seconds rallies, video ≤30 seconds signs local. Operator overrides via chain-anchored preference.

**Composition with SUBSTRATE-FORM-2026-07.md's inference-sourcing axis:** same architectural pattern (some work runs local, some rallies to workstation-class hardware). Not a coincidence — both reflect the general "cheap-edge-device + rally-when-needed" shape of Sovereign Form realization.

---

## Part V — KMS BYOK precedent

AWS KMS added "external key material" (BYOK — bring your own key) support because enterprise customers wanted trust roots outside AWS's control. Under BYOK, the customer generates key material externally (HSM, on-prem key management, air-gapped ceremony) and imports it to KMS. AWS-hosted operations use the key, but AWS never held the private key material at generation time.

This is the same architectural instinct as ZP's operator-held key, applied at enterprise scale. **The pattern is proven at scale; ZP's version is just moving the key custody further toward the operator** — from BYOK-to-cloud to fully-substrate-held-and-never-uploaded.

**What this validates about ZP's approach:**

- The market has already accepted "customer holds the trust root, cloud service uses it via signed request" as a viable architectural pattern for high-assurance customers.
- The cloud provider's role becomes "signing service that uses customer's key" rather than "signing authority that owns the key." That's a coherent architectural role that many cloud services already fulfill.
- ZP substrate can play the same role for the operator that KMS-with-BYOK plays for enterprise customers — but at the operator's scale, with the substrate as the "cloud service" analog running on the operator's own hardware.

**What ZP does that BYOK doesn't:**

- BYOK still requires customer-cloud coordination for signing (network round-trip to cloud KMS per signature). ZP substrate-local signing has no network hop.
- BYOK's audit trail is the cloud provider's (CloudTrail); ZP's audit trail is the operator's own chain.
- BYOK's key rotation is cloud-mediated; ZP's per `GENESIS-ROTATION-CEREMONY-2026-07.md`.

**Reference this precedent when explaining ZP's model to operators familiar with enterprise KMS patterns.** The learning curve is shorter when the operator can map "substrate media signing = KMS with BYOK, but the KMS runs on my own hardware."

---

## Part VI — Certificate lifecycle across Genesis rotation

Mainstream C2PA infrastructure treats signing certificates as static — provisioned once via Secrets Manager or KMS, used for the lifetime of the campaign or product. Rotation is possible but not architecturally central.

ZP has active Genesis rotation per `GENESIS-ROTATION-CEREMONY-2026-07.md`. When the operator rotates Genesis (compromise-suspected, preventive, recovery, or migration), every downstream signing key derives from the new Genesis. Existing signed manifests must remain verifiable across the rotation.

**Discipline:**

- Every media provenance receipt embeds its full certificate chain from operator signing key back to Genesis at time of signing.
- Genesis rotation ceremony chain-anchors `genesis:rotated:<from>:<to>` receipts. Post-rotation verifiers can look up whether a signature over a manifest was produced by an active-at-the-time key (verifiable by comparing the manifest's timestamp against the rotation chain).
- Rotation does NOT invalidate prior signatures. Chain is truth; the signature was valid when made; the rotation is chronology, not repudiation.
- Post-rotation-produced media provenance uses the new key; the chain records the transition.

**Composition:** operator can inspect any media provenance receipt via `zp media provenance verify <receipt_id>` and see: signature valid, certificate chain intact, key was active at signing time, chain evidence for signing invocation exists. Four checks, all chain-anchored, together prove the receipt is trustworthy.

**Rotation-aware verification behavior for external verifiers:** when a C2PA-consuming external tool encounters a ZP-signed manifest, the manifest carries certificate-chain-in-manifest per C2PA spec. If the operator has rotated Genesis since signing, the certificate chain in the manifest references the pre-rotation certificate. External verifier accepts if the pre-rotation certificate was valid at manifest timestamp AND the chain composes back to a Genesis root the verifier trusts. This is standard C2PA semantics; ZP's contribution is making the rotation chain-visible so operators can prove pre-rotation-signature validity even years post-rotation.

---

## Part VII — Interoperability threat model

Naming the specific attacks this discipline is designed to compose with or defend against:

**Vendor PKI compromise (Nikon-class incident):** external attacker compromises a camera vendor's signing infrastructure and produces valid-looking manifests without physical device involvement. ZP's per-operator trust root reduces blast radius to the operator's own key custody. If ZP substrate is compromised, only that operator's media is affected; if a camera vendor's PKI is compromised, every device in the vendor's fleet is affected.

**Custom-signer endpoint impersonation:** malicious process on the operator's device attempts to call the substrate's custom-signer endpoint to sign forged content. Defended by gate enforcement + operator-signed delegation-per-tool. Only tools with active `capability:media:sign` delegation succeed; substrate refuses signing requests from tools without delegation. Chain-anchored refusal is evidence of the attempt.

**Signing key extraction from substrate:** malicious process gains code execution on the operator's substrate and attempts to extract the signing key. Defended by:
- Singular sovereign root discipline (Genesis material is unwrapped once at boot and lives in memory only; not on disk unencrypted).
- Sovereignty provider integration (Trezor / YubiKey holds Genesis-derivation key; substrate holds derived signing material for the session but never the underlying root).
- Post-compromise recovery via Genesis rotation ceremony.

**Manifest tampering post-signing:** attacker modifies the media file's manifest data after signing. Defended by C2PA-standard mechanisms (manifest hash covers the media bytes; signature covers the manifest hash). Any modification invalidates the signature.

**Downstream re-signing / laundering:** attacker takes signed media, extracts the media bytes, re-encodes, and either signs with their own key or presents unsigned. This is a general C2PA limitation (per `MEDIA-PROVENANCE-2026-07.md` §10.2) — provenance is per-instance, not intrinsic to the media. ZP does not defeat this class; it composes with C2PA's "chain of authorship" semantics where the re-signed instance carries evidence of derivation from an unsigned source.

**Rotation-timing attacks:** attacker signs content with a pre-rotation-compromised key AFTER rotation should have taken effect. Defended by chain-anchored rotation receipts with signed timestamps: verifiers can detect that a manifest claiming pre-rotation timestamp actually contains post-rotation-signed content.

---

## Part VIII — Composition with existing specs

- **`MEDIA-PROVENANCE-2026-07.md`** — this document elaborates the interoperability composition patterns for the base MEDIA-PROVENANCE architecture. Parts II-IV here elaborate implementation details for the "receipt structure" and "verification workflow" that MEDIA-PROVENANCE defines.
- **`ENCRYPTED-STORAGE-ARCHITECTURE-2026-07.md`** — the substrate-hosted signing key derivation composes with the vault key derivation both anchored at Genesis. Same singular-sovereign-root discipline.
- **`GENESIS-ROTATION-CEREMONY-2026-07.md`** — Part VI's certificate lifecycle across rotation composes directly with the rotation ceremony's four-phase flow.
- **`MULTI-DEVICE-OPERATION-2026-07.md`** and rally primitive — Part IV's substrate-local vs rallied signing split composes with fleet compute-rally.
- **`QUARANTINE-PLANE-2026-07.md`** — Part III's custom-signer endpoint is a substrate admission surface for external tool signing requests. Same admission ceremony discipline.
- **`SUBSTRATE-BOOT-INVARIANT-CEREMONY-2026-07.md`** — the `media_signer` surface becomes a composition-matrix dependent surface. Adding a new sovereignty provider must verify media-signing composes (same discipline as tonight's audit-signer / vault-key / CLI-load pattern).
- **`REPRODUCIBILITY-CEREMONY-2026-07.md`** — peer verification of media provenance signatures composes with the peer verification ceremony.
- **`SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md`** — aligned blindness applies: media provenance receipts do NOT include blind-class data (biometric identifiers, credential values, location-at-non-public-times). Only what the operator has authorized inclusion of.
- **`SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md`** — cross-operator media provenance verification (peer signature validation, familiarity accumulation) composes with kinship primitives.

---

## Part IX — What this document does NOT decide

- **ZP Camera App implementation shape.** Part 8 of MEDIA-PROVENANCE-2026-07.md is that scope. This document informs the app's signing architecture; it does not specify the app.
- **Which C2PA manifest schema version to target.** C2PA 2.x is current; version-tracking is per emission, not per architecture.
- **Non-C2PA provenance schema support.** Some ecosystems (photo forensics, journalism-specific tooling) use non-C2PA schemas. Not addressed here.
- **AI-generated media detection.** Per MEDIA-PROVENANCE-2026-07.md §10.6, this is a separate concern; ZP composes with C2PA's declared-AI-generation markers but does not solve AI detection.
- **Cloud media pipeline for large-scale enterprises.** ZP is operator-scale sovereign infrastructure; enterprises using ZP for individual operator-level provenance is coherent; enterprises deploying ZP as their signing pipeline for millions of assets is not the design target.

---

## Part X — Follow-up work

**Immediate (informs the ZP Camera App):**
- Decide dual-sign (Approach C) vs Ed25519-only (Approach B) default for the app.
- Author the C2PA custom-signer endpoint specification.
- Populate model dossier entries for the ES256 signing algorithm (if Approach A or C).

**Near-term (once the app is being implemented):**
- Reference implementation of the custom-signer wedge tested against Adobe Content Credentials.
- Test suite validating ZP-signed manifests against C2PA reference verifier libraries.
- Documentation for operators explaining "substrate signing = KMS-with-BYOK, on-device" framing.

**Longer-term:**
- Peer-verification protocol extension for cross-operator media provenance validation.
- Kinship-scoped media provenance sharing (per SOVEREIGN-KINSHIP-PRIMITIVES).
- Certificate-rotation-aware verifier libraries for tools that want native ZP awareness.

**Speculative:**
- Camera-hardware integration (hardware sensor attestation composing with substrate signing) — depends on availability of C2PA-hardware SDKs from camera vendors and their willingness to integrate with third-party trust roots.
- Video-editing-in-substrate reference implementation (avoids the round-trip to Adobe entirely for operators willing to use substrate-native tools).

---

## Composes with / connects to

- **MEDIA-PROVENANCE-2026-07.md** — this document is the interoperability companion.
- **GENESIS-ROTATION-CEREMONY-2026-07.md** — certificate lifecycle across rotation.
- **MULTI-DEVICE-OPERATION-2026-07.md** — substrate-local vs rally signing tier.
- **SUBSTRATE-BOOT-INVARIANT-CEREMONY-2026-07.md** — media_signer as composition-matrix dependent surface.
- **QUARANTINE-PLANE-2026-07.md** — custom-signer endpoint as admission surface.
- **REPRODUCIBILITY-CEREMONY-2026-07.md** — peer verification of media signatures.
- **SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md** — aligned blindness in media provenance content.
- **SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md** — cross-operator provenance sharing.
- **VAULT-KEY-SOVEREIGNTY-COMPOSITION-2026-07.md** — same singular-sovereign-root discipline applied to media-signing key derivation.

## CLAUDE.md workflow heuristics this exercises

- *Singular sovereign root: one authentication, everything derived.* — the media-signing key derives from Genesis alongside the audit signer, vault key, delegation keys. No independent trust root for media.
- *A tool is intent, crystallized.* — the custom-signer endpoint is intent-crystallized: operator has declared media-signing capability delegation; substrate emits per invocation; each signature IS the operator's crystallized intent to attest this media.
- *When two reasonable architectural models conflict over the same surface, half-state is the failure mode.* — dual-sign (Approach C) resolves the Ed25519-vs-ES256 tension without half-state; choose-one-and-drop-the-other is the failure shape.
- *Silence is the enemy, not compromise.* — custom-signer refusals are chain-anchored, not silent. Every signing decision produces evidence.
- *Coordination, not oversight.* — cross-operator provenance verification uses kinship discipline; no categorical surveillance of who is signing what.
- *Aligned blindness is a moral property of the substrate.* — media provenance manifests avoid blind-class content, structurally.

## Proposed new heuristic (nomination for CLAUDE.md)

**Interoperability is composition, not conformity.**

*A substrate that stands for sovereignty does not need to reject the existing ecosystem's data models, cryptographic primitives, or tooling to preserve its architectural claim. It needs to compose with them in a way that preserves the trust root. The mainstream ecosystem's schema is a shared language; the trust anchor is what defines whose claim is being made.*

*Concretely: use C2PA's manifest structure (composition), sign with the operator's own key (sovereignty preservation). Use Adobe's editing tools (composition), sign against the substrate's custom-signer endpoint (sovereignty preservation). Use standard verifier libraries (composition), embed certificate chains that trace to operator Genesis (sovereignty preservation).*

*The failure mode this heuristic catches: rejecting a widely-adopted ecosystem primitive because "we do it differently" — losing interop for architectural purity that operators don't actually need. The success mode: adopting the primitive AS DATA MODEL while replacing the trust anchor with the substrate's sovereignty-consistent one. Ecosystem participates; substrate preserves its thesis.*

*Applies at every substrate ↔ ecosystem boundary: media provenance (C2PA), DLT composition (Hedera / Ethereum), cognitive layer (open-source SLMs), identity federation (WebAuthn / OIDC), any standard where the ecosystem's shared data model is worth adopting but the ecosystem's trust root is not.*
