# Onboarding Flow — July 2026

**Document type:** Design note. Specifies the sequence of decisions and interactions a new operator walks through during their first fifteen minutes with ZeroPoint. This is architectural, not just UX — every decision made during onboarding anchors downstream behavior. Gets Genesis, first Regent contact, first mandate, and first context right; defers what should be deferred; refuses to overwhelm.

**Status:** Design note. Ready for iteration; open decisions marked.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-05.

---

## Part I — What the First Fifteen Minutes Must Do

Onboarding is where the operator forms their working model of the substrate. If those first minutes teach them that ZeroPoint is a wall of decisions and jargon, they leave. If those minutes teach them that ZeroPoint is a sovereignty-preserving cognitive collaborator that respects their attention, they stay and grow.

The substrate has structural properties (Genesis-derived identity, chain-anchored governance, singular sovereign root, mesh-native coordination) that are load-bearing but not intuitive. Onboarding's job is to make the load-bearing decisions consequential and correct while introducing only the concepts the operator needs to make them.

Onboarding must:

- **Establish sovereign identity.** Genesis ceremony is done properly, with a real sovereignty provider bound.
- **Introduce the Regent as a collaborator.** Not a tutorial; a first real interaction where the Regent behaves as they will continue to behave.
- **Set the first mandate.** The Regent needs scoped authority to help; the operator grants it explicitly.
- **Give the operator somewhere to be.** A first community context, or an explicit solo start.
- **Leave the operator competent.** After onboarding, they know how to do the next thing they will want to do.

Onboarding must not:

- **Overwhelm.** A dozen decisions in the first five minutes produces bounce.
- **Force irrevocable choices too early.** Decisions with long-term consequences require the operator's real attention; they can be deferred until the operator has enough context to make them well.
- **Feel like a tutorial.** The operator is talking to the Regent from the beginning; onboarding is a real conversation, not a scripted walkthrough.
- **Front-load philosophy.** Sovereignty, chain-anchored governance, the trust-grammar — these will make sense as the operator engages. Explaining them upfront produces glaze.

---

## Part II — Design Principles

Six principles shape the flow.

**1. Progressive disclosure.** Complexity surfaces as the operator engages with it, not upfront. The Regent teaches by presenting the next-relevant decision at the moment it becomes relevant.

**2. The Regent is the guide.** No separate tutorial system. The Regent walks the operator through onboarding as their first real conversation. What they learn about the Regent during onboarding is how the Regent will behave from that point forward.

**3. Real decisions, real consequences.** Every choice the operator makes during onboarding produces a chain-anchored effect. Nothing is theatrical. The Genesis ceremony is Genesis. The first mandate is a real mandate. The subscription filter is a real filter.

**4. Deferability is a feature.** Anything the operator doesn't need to decide in the first fifteen minutes can be deferred without penalty. Onboarding surfaces the load-bearing decisions and marks the rest as "we can come back to this."

**5. Reversibility protects the operator.** Where irrevocability is architecturally required (Genesis, ceremonial linking, certain constitutional bindings), the operator sees that irrevocability clearly. Where reversibility is possible, the operator is told they can change their mind later.

**6. Sovereignty preserved throughout.** No coercive dark patterns. No decisions bundled with functionality so declining feels like losing something. Every ask is a real invitation, and declining is a valid answer with no consequence beyond the specific capability declined.

---

## Part III — The Onboarding Sequence

Six stages. Not every stage requires operator interaction — some are pre-Genesis substrate setup that happens transparently. Onboarding sequence assumes the operator has installed a verified ZeroPoint build (see §VI on bootstrap trust).

### 3.1 Stage 1: Verified installation

Before onboarding proper begins, the operator's substrate verifies its own installation. The release hash matches a chain-anchored release receipt from a trusted authority (Foundation-signed, or a community authority the operator has previously verified). If verification fails, onboarding refuses to proceed with an explanation of why.

This stage is invisible to the operator when it succeeds. Its purpose is to ensure that the substrate the operator is about to trust with Genesis has not been tampered with.

### 3.2 Stage 2: Genesis ceremony

The most consequential decision the operator will make. The Regent (running as a pre-Genesis skeleton — no persistent memory, no context, just enough to walk the ceremony) introduces it plainly:

*"You're about to create your ZeroPoint identity. This is the root of everything you'll do here — messages you send, communities you join, decisions you make. Your identity will belong to you, cryptographically. No one — including me, including the Foundation that built this software — can revoke it, override it, or condition your use of it. Ready?"*

The operator:

1. **Chooses a sovereignty provider.** The Regent presents the options available on their device (Secure Enclave / StrongBox / TPM / hardware wallet / passphrase fallback) with a brief plain-language explanation of each. The default recommendation depends on the device's capabilities; the operator can accept or select otherwise.
2. **Authorizes the ceremony.** The operator uses their chosen provider to authenticate. The Genesis keypair is generated in secure hardware.
3. **Sees the resulting identity.** The Regent shows the operator's newly-created public identity fingerprint (short, memorable — the first eight hex characters, or a word-mnemonic representation) so they know what their identity looks like to peers.
4. **Backs up.** The operator is presented with immediate backup options (see §V.4). At minimum, a seed phrase is shown once with clear instructions to write it down.

The Genesis ceremony is atomic and irreversible. The Regent makes this explicit before it begins.

### 3.3 Stage 3: Meeting the Regent

The Regent introduces themselves as a working collaborator, not a chatbot:

*"I'm the Regent — your cognitive collaborator inside this substrate. I represent you here. I'm going to help you do things, and I'm going to ask before doing anything consequential. Everything I do produces a receipt on your chain, so you can always see what I've done and why."*

The introduction includes:

- **What the Regent is.** Cognitive layer that runs on the operator's own hardware, uses configurable inference (defaults to local model), governed by the same substrate as any other component.
- **What the Regent isn't.** Not a service. Not a subscription. Not a listener that phones home. Not the Foundation acting on the operator's behalf.
- **How the Regent asks for things.** Consequential actions get explicit approval; routine ones happen within the operator's established mandate.

The operator can name the Regent if they want (per the whitepaper's note that the Regent title is relational and temporary). Or they can leave the title as-is and revisit later.

### 3.4 Stage 4: First mandate

The Regent needs scoped authority to be useful. The first mandate is the operator's explicit grant:

*"To help you do things, I need some authority you'll grant me — and revoke or change at any time. I'd like permission to: run officer sweeps on your chain; propose actions for your approval; use the local inference model you've installed; and use a small amount of your device's storage for my memory. Nothing here talks to the outside world without a separate approval. Grant this?"*

Presented as a single mandate with clearly-listed scope. The operator sees exactly what they're authorizing and what they're not. Signing the mandate is a chain event.

Additional mandates (cloud inference, browser control, community publishing, contact-book access) are presented later when the operator engages with those capabilities. Not front-loaded here.

### 3.5 Stage 5: First community context

Every operator needs to be *somewhere* — inside some coordination context, even if that context is "on my own for now." The Regent presents the choice:

*"Do you have somewhere you want to be first? A community you've been invited to? An operator you know already? Or would you like to start alone and see what's out here at your own pace?"*

Three paths from here:

**Invitation.** The operator has an invite code, a QR from a community, a link from a peer. The Regent walks them through joining. First bounded-space or portable-space identity decision happens here.

**Known peer.** The operator wants to reach someone specific (name, phone number, other identifier). The Regent explains the introduction ceremony pattern (per `PHONE-AND-IDENTITY-2026-07.md`) and helps them initiate first contact.

**Alone-for-now.** No community, no known peer. The Regent explains they can subscribe to some Foundation-reserved channels (`community:general`, `community:governance`) or explore later. Sets minimal subscription filters (nothing beyond what the operator wants).

None of these paths is discouraged. The alone-for-now path is a first-class start; the operator is not made to feel they need to be plugged into something to matter.

### 3.6 Stage 6: First real interaction

Onboarding ends with a real conversation, not a "you're done" screen. The Regent asks:

*"What's the first thing you want to do here?"*

Whatever the operator says — draft a message, look at a chain, explore what tools are available, understand something about how the substrate works — the Regent handles it directly. Not by pointing at a documentation page. Not by launching a tutorial. By doing the thing, showing the receipts as they happen, and being available for follow-up.

If the operator has nothing specific in mind, the Regent can suggest options based on what makes sense given the paths chosen in Stage 5. But the Regent does not force an interaction; the operator can also just say "I'll come back to this later" and the substrate remembers exactly where they were.

---

## Part IV — The Regent During Onboarding

The Regent's behavior during onboarding is the operator's first read on who the Regent will be. This is not a demo mode.

**Same tone as always.** Warm, direct, service-oriented, honest about limits. The healthy Two personality that ships as the substrate's default is fully present from the start.

**Explains only when needed.** The Regent does not lecture on sovereignty, chain-anchored governance, or the philosophy of the substrate. Those topics come up when they become relevant to a specific decision. If the operator asks, the Regent answers plainly. If they don't ask, the Regent doesn't front-load.

**Names uncertainty honestly.** If the operator asks something the Regent doesn't know (a substrate capability that hasn't shipped yet, a community-level norm that varies by community, a design decision the Foundation hasn't made), the Regent says so plainly rather than inventing an answer.

**Records what happens.** Every step of onboarding produces chain receipts. The operator can see afterward what they authorized, what the Regent did, and why.

**Respects the operator's time.** If the operator says "I want to skip ahead," the Regent skips ahead with a note about what was deferred and how to come back. If the operator says "I need to step away," the substrate holds state and picks up where they left off.

**Available for follow-up.** After onboarding, the operator can ask the Regent about anything that happened during onboarding — "why did you recommend Secure Enclave over the hardware wallet?" — and get a real answer with reference to the specific decision moment.

---

## Part V — What Gets Deferred

Not everything worth eventually deciding needs to be decided in the first fifteen minutes. Onboarding defers what can be deferred and marks it clearly.

### 5.1 Deferred without prompt

The substrate does not proactively raise these during onboarding. The operator will encounter them when they matter:

- **Phone attestation.** No default prompt. Introduced only if the operator invokes an introduction ceremony that would benefit from it.
- **Cloud inference mandate.** No default prompt. Introduced when the operator hits a task that would benefit from cloud escalation.
- **Multi-device provisioning.** No default prompt. Introduced when the operator wants to add a second device.
- **Peer chain replication.** No default prompt. Introduced when the operator asks about backup or when Aegis suggests it.
- **Real-name attestation.** No default prompt. Ever.
- **Advanced subscription filters.** No default prompt. Basic subscriptions during Stage 5; refinement over time.
- **Adaptive personality participation.** No default prompt. The Two personality serves. If the validation protocol eventually clears, that's a future opt-in decision.

### 5.2 Deferred with a light note

The Regent mentions these once during onboarding and moves on. They accumulate as small backlog items the operator can address when ready:

- **Additional backup mechanisms** beyond the seed phrase shown during Genesis. "We should also set up peer chain replication or a hardware wallet backup sometime — you can ask me when you're ready."
- **Community discovery beyond initial subscriptions.** "There are more communities out there. I'll surface ones that seem relevant as you engage."
- **Migration path from other identity systems.** If the operator mentions they're coming from a specific platform, the Regent notes there are patterns for bringing over some kinds of state — but doesn't push.
- **Contribution to the commons.** "You'll accumulate patterns as you work. When you want, we can talk about sharing some of them with the ecosystem."

### 5.3 Never deferred

Some decisions are load-bearing enough that onboarding requires them:

- **Genesis ceremony.** Cannot be deferred; onboarding does not proceed without it.
- **Sovereignty provider choice.** Genesis requires binding to a provider; cannot be deferred.
- **First mandate to the Regent.** The Regent cannot help without scope; onboarding requires the operator's initial mandate.
- **At least a starting backup mechanism.** A seed phrase is shown during Genesis regardless of what else the operator sets up later.

### 5.4 Backup during Genesis

The seed phrase is shown once, immediately after Genesis, with clear instructions. The Regent verifies the operator has recorded it by asking them to confirm they've written it down (not by asking them to re-enter it — that would train them to keep it accessible on the same device).

Additional backup options (peer chain replication, hardware wallet, M-of-N Shamir shares) are noted in §5.2 as deferred with a light touch. The seed phrase alone is not the recommended final backup posture; it is the minimum viable initial backup.

---

## Part VI — Bootstrap Trust

The operator has to trust *something* to begin. Onboarding minimizes what they have to trust and makes what remains verifiable.

### 6.1 The trust chain during onboarding

- The operator downloaded a specific binary.
- That binary claims to be a signed release from the Foundation (or another release-signing authority).
- The signature is verifiable against a public key.
- The public key was distributed through some out-of-band channel (a website, print, physical media, personal network) that the operator has some basis to trust.

The substrate does not require the operator to trust the network they downloaded over, or the DNS resolver that pointed them at the download, or the ISP that carried the bits. The signature is checked against the key the operator has already accepted.

Verification failure is a hard stop. The Regent explains what failed and refuses to proceed.

### 6.2 What the operator learns to verify

During onboarding, the Regent shows the operator:

- **The release signature check.** "This build was signed by [authority]. I verified the signature. You can verify it too."
- **The chain's Genesis receipt.** The Genesis event that just happened is chain-anchored; the operator can see it, and every subsequent action will link to it.
- **The Regent's own attestation.** Which model the Regent is running, from which build, with what declared capabilities.

Verification is presented as a thing the operator can do at any time, not as a one-time step. The mechanisms are visible.

### 6.3 The Foundation's role during onboarding

The Foundation appears in onboarding only in specific, bounded ways:

- **As release-signing authority** for the Foundation's reference build (if that's what the operator installed).
- **As convenience seed peer** for initial community discovery.
- **As author of the software and its documentation.**

The Foundation is not a coordinator, not an account provider, not a required intermediary for anything. Nothing about onboarding requires the Foundation to be online, reachable, or continuing to exist.

---

## Part VII — Recoverability During Onboarding

Onboarding can be interrupted. Devices die. Attention wanders. The operator changes their mind. The substrate handles each of these gracefully.

### 7.1 Interruption before Genesis

Anything before Genesis is discarded on exit. The operator can restart onboarding without consequence. Sovereignty provider choice, name preferences, community interests — none of this is persisted before Genesis because there is no Genesis-derived identity yet to attribute it to.

### 7.2 Interruption after Genesis, before first mandate

Genesis is atomic and complete. If onboarding is interrupted after Genesis but before the first mandate, the operator's identity exists but the Regent cannot yet do anything on their behalf. On next launch, onboarding resumes at the mandate step. The Regent is available for direct conversation but cannot take autonomous action.

### 7.3 Interruption after first mandate

The mandate is chain-anchored. The Regent has scoped authority. If onboarding is interrupted at Stage 5 or 6, the Regent picks up where they left off next launch. The operator hasn't lost anything; they just haven't finished exploring.

### 7.4 Wanting to start over

Sometimes an operator goes through onboarding, decides they made a mistake, and wants to start clean. The substrate accommodates:

- **Discard the Genesis identity.** A supersession receipt marks the current Genesis as abandoned. The operator performs a new Genesis ceremony. Old chain state remains on disk (for auditability) but the operator's operational identity is the new Genesis.
- **Alternative: revoke specific decisions.** If the operator only wants to undo specific mandates or subscription choices, those are individually revocable without Genesis restart.

Starting over is a real option, presented as such, without penalty. Not something the operator has to find in an obscure settings menu.

---

## Part VIII — Failure Modes to Guard Against

Naming what onboarding must not become.

### 8.1 The wall of consent

Every consequential system decision presented at once, with legal-language explanations, expecting the operator to click through to proceed. Standard SaaS onboarding pattern. Fatal for a substrate that expects informed consent to be real. Prevented by progressive disclosure and by refusing to bundle unrelated decisions.

### 8.2 The tutorial trap

Onboarding as a scripted walkthrough separated from real use. The operator learns about a demo world that doesn't correspond to how the substrate actually behaves. Their model breaks the moment they hit real use. Prevented by making the Regent's onboarding behavior identical to the Regent's ongoing behavior.

### 8.3 Philosophical front-loading

Explaining sovereignty, chain-anchored governance, cryptographic identity, and the whole trust-grammar model before the operator can do anything. Produces glaze. Prevented by trusting the operator to learn what they need as they need it, not all at once.

### 8.4 Coercive defaults

Defaults that steer the operator toward decisions convenient for the Foundation, the reference implementation, or any specific party. Sovereign systems have defaults, but the defaults should serve the operator's likely needs, not the substrate's political convenience. Prevented by explicit review of every default in this document.

### 8.5 Terrified onboarding

Introducing Genesis with so many warnings and caveats about the consequences of losing the seed phrase that the operator becomes afraid to proceed. Real risk needs real communication, but the tone stays confident. Prevented by presenting risks matter-of-factly with recovery options named alongside.

### 8.6 Isolation

Ending onboarding without giving the operator any way to reach anyone else or find any community. The alone-for-now path is fine; unintended isolation is not. Prevented by Stage 5 explicitly presenting the three paths (invitation / known peer / alone-for-now) as equal choices.

---

## Part IX — Open Design Decisions

1. **Sovereignty provider defaults per device class.** What the Regent recommends by default on iOS vs. Android vs. Linux vs. hardware wallet available. Depends on threat model calibration.

2. **Seed phrase format.** BIP-39, SLIP-39, or ZP-native? Composes with backup-and-recovery choices.

3. **Regent introduction copy.** The specific opening line the Regent uses matters. Should reflect the Two personality accurately; deserves iteration with real users.

4. **First-mandate scope.** What's the minimum scope for the Regent to be useful without asking for too much upfront? Recommendation in §3.4 is a starting point.

5. **Community-discovery seed set.** What Foundation-reserved channels the Regent subscribes to by default in the "alone-for-now" path. Which are essentially required (security advisories) vs. optional (general discussion).

6. **Interruption resume UX.** How the substrate presents itself on relaunch if onboarding was interrupted at a specific stage.

7. **Multi-language onboarding.** English is the default; localization strategy for other languages including cultural adaptation of tone.

8. **Accessibility of the Genesis ceremony.** Screen reader compatibility, high-contrast mode, alternative input methods for operators who can't use standard biometric flows.

9. **First-fifteen-minutes measurement.** How the ecosystem measures whether onboarding actually works, without violating operator sovereignty by phoning home about specific-operator progress. Aggregate anonymous signal from opt-in operators, if at all.

10. **Migration paths from other systems.** For operators coming from specific platforms (Signal, Matrix, Nostr, other sovereign-ish systems), what state can be imported and how.

11. **Onboarding-mode Regent capabilities.** During the pre-mandate portion of onboarding, the Regent is running in a limited mode. What exactly can it do? What does it need to be able to do?

12. **Verified-installation failure UX.** When release signature verification fails, what does the Regent tell the operator, and what remediation paths does it offer?

---

## Part X — Companion Documents

- `docs/whitepaper-v9.md` — §5.5 (Genesis and key hierarchy) is the substrate mechanism this document walks the operator through in Stage 2.
- `docs/ARCHITECTURE-2026-07.md` — the singular sovereign root principle that Genesis instantiates.
- `docs/design/MULTI-DEVICE-OPERATION-2026-07.md` — the provisioning flow this document initiates. First device is provisioned implicitly at Genesis.
- `docs/design/BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md` — the compositions the operator will eventually adopt beyond the initial seed phrase.
- `docs/design/ENCRYPTED-STORAGE-ARCHITECTURE-2026-07.md` — the vault format the sovereignty provider seals.
- `docs/design/REGENT-COMPARTMENTALIZATION-2026-07.md` — the Regent's role as the operator's cognitive advocate begins at onboarding.
- `docs/design/PHONE-AND-IDENTITY-2026-07.md` — the introduction ceremony pattern used in Stage 5's "known peer" path.
- `docs/design/COMMUNITY-SURFACE-ARCHITECTURE-2026-07.md` — the community context Stage 5 introduces.
- `docs/design/COMMUNITY-COORDINATION-ON-ZEROPOINT-2026-07.md` — the bootstrap trust model that onboarding depends on.
- `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md` — how the operator finds communities and how the Foundation reaches them via announces.
- `docs/design/SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md` — the verified installation check in Stage 1.
- `docs/design/TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md` — Aegis and the officers begin producing findings once the first mandate is granted.

---

*The first fifteen minutes are architectural. Get Genesis right, introduce the Regent as themselves, grant a scoped first mandate, place the operator somewhere they want to be, and end with a real conversation. Defer what can be deferred. Let complexity surface as the operator engages with it. The operator leaves onboarding as a full participant, competent to do the next thing they want to do, holding an identity that is provably theirs, in a substrate that has done nothing behind their back.*
