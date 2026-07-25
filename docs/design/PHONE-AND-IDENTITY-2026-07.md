# Phone and Identity — July 2026

**Document type:** Design note. Establishes the canonical position on how phone numbers relate to ZeroPoint identity — neither identity nor required, but gracefully composable with the association reality that most human relationships are bootstrapped through phone numbers. Sits under `ARCHITECTURE-2026-07.md` Part I (there is no center; identity is a key, not a location) and composes with `REGENT-COMPARTMENTALIZATION-2026-07.md` on how the operator maintains identity boundaries.

**Status:** Design note. Ready for iteration; open decisions marked.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-05.

---

## Part I — The Association Reality

Phone numbers are meaningless in themselves — ten digits with an area code. But *association* makes them identity. A friend's phone number is functionally "that friend" in your address book, at their bank, at every service that ever asked them for a number. When someone new gets that number after it's abandoned, they inherit some of the identity association whether they want to or not.

This is different from ZP's cryptographic identity. A Genesis-derived key is meaningful in itself — it's provably yours because you performed the ceremony that produced it. A phone number gains meaning only through the social association that says "this number belongs to that person." The two identity models are fundamentally different: one is intrinsic, one is associative.

The tension is real: ZP's philosophy says identity is a key, not a location. Phone number is a location. So phone number is fundamentally not identity in the substrate. But operators don't live in the substrate alone — they live in a world where most of their relationships were bootstrapped through phone numbers, most of their service accounts require phone numbers, and most of their friends and family will think of "reaching them" as calling a number.

Ignoring this reality is adoption-hostile. Baking it into identity is sovereignty-hostile. This document specifies the middle posture.

---

## Part II — Two Failure Modes to Avoid

### 2.1 Failure Mode: Ignoring phone reality

ZP identity is pure crypto; phone numbers are irrelevant; operators onboard via Genesis ceremony and find each other via peer discovery only. This is architecturally clean and adoption-hostile. New operators can't easily find their existing friends. Existing services that require phone numbers still do, and now the operator manages a schism between "my ZP identity" and "my real-world identity." Most operators bounce.

### 2.2 Failure Mode: Baking phone into identity

ZP identity is tied to phone number (Signal's original model). Onboarding requires a phone. Contact discovery uses phone number lookup. Then: SIM swap compromises identity, phone number becomes a de-anonymization vector, ZP identity leaks into every advertising database that has your phone number, and the sovereignty property collapses because phone-issuing carriers become a trust dependency. Signal has spent years unwinding this decision.

### 2.3 The right posture

Phone is neither identity nor required, but the ecosystem gracefully handles the association reality through four composable affordances.

---

## Part III — Four Composable Affordances

### 3.1 Phone attestation as optional, revocable, scope-bounded

An operator can publish a chain-anchored attestation: "ZP identity Y controls phone number X at time T." Properties:

- **Optional.** No ZP-native function requires phone attestation.
- **Scope-bounded.** Attestation can be visible to a specific bounded space, to a portable context, or to specific peers explicitly. Not automatically ecosystem-wide.
- **Revocable.** A chain receipt at any time revokes the attestation. Peers who had visibility respect the revocation going forward.
- **Verified but not enforced.** The attestation is produced via challenge-response (operator receives an SMS containing a nonce, responds via signed ZP receipt containing the nonce). This proves control of the phone number at attestation time. Future control is not guaranteed.

The attestation is a bridge to the non-ZP world for operators who want the bridge. It is not a coordinate the substrate uses for anything.

### 3.2 Introduction ceremonies bootstrap via phone but graduate to ZP

Alice has Bob's phone number in her address book but doesn't yet know his ZP identity. The bootstrap flow:

1. Alice sends Bob an SMS containing a ZP introduction challenge — an ephemeral URL or QR-like payload that encodes an introduction request signed by Alice's ZP identity.
2. Bob receives the SMS. His ZP client (or the ZP camera app scanning a QR code) reads the payload, verifies the signature.
3. Bob decides whether to introduce himself. If yes, his ZP client emits a signed introduction receipt back to Alice.
4. Alice's ZP client receives the receipt via mesh (or via a return SMS carrying a ZP payload for constrained-transport scenarios).
5. Alice and Bob now have a ZP-native relationship. Both have added the other to their respective contact structures under their ZP identities.

From that point, phone is out of the loop for the ongoing relationship. Phone was the bootstrap channel, not the ongoing identity substrate. This is the pattern modern secure messengers approach with QR-code identity verification, adapted for phone-mediated first-contact.

### 3.3 Contact book integration stays local

The operator's phone contact book stays entirely on their device. When ZP wants to help the operator find people:

- **Local match.** Check phone contacts against known-ZP-identities from prior introductions. Match locally. No directory lookup.
- **Contacts without corresponding ZP identity remain phone-only contacts.** The operator can reach them via phone or SMS but not via ZP. The Regent surfaces this: "Ken is a phone contact; he's not on ZP that you know of. Reach him via phone?"
- **No hash-based directory service.** ZP does not hash phone numbers and check them against a Foundation directory. No "who else on ZP might you know" via phone-number lookup. Contact discovery is explicit, one relationship at a time.
- **No cross-operator contact sharing.** The operator's contact book is theirs. It's not synced with peers, not shared with the Foundation, not aggregated anywhere.

The Regent may help the operator maintain and organize their contacts, but the operator's contact book is a private local artifact.

### 3.4 Phone as fallback channel, not primary

For operators who want to be reachable when mesh transport isn't available, phone/SMS can carry ZP receipts:

- **SMS-embedded receipts.** A ZP receipt small enough to fit in SMS payload (with URL-encoded compact form) can be sent as SMS. Recipient's client parses and processes normally.
- **URL-based invitations.** Receipts too large for SMS can be represented as URLs pointing at ephemeral pickup locations, sent via SMS. Recipient opens the URL; their client fetches and processes.
- **Not required.** This is optional transport, not primary. The mesh substrate is primary.

Every SMS ZP sends is a receipted decision, not automatic. The Regent might send an SMS on the operator's behalf when the recipient isn't ZP-reachable, but the operator sees this as a proposed action, not a background behavior.

---

## Part IV — The Specific Advantages

The posture in Part III yields concrete advantages over identity systems that anchor to phone numbers:

### 4.1 SIM swap has no effect on ZP identity

If your SIM is hijacked, your ZP identity is intact. Because your ZP identity is not derived from or attested by your phone number in any structural way, control of your phone number does not confer control of your ZP identity.

Consequence: any phone attestations you had can be revoked and re-issued once you regain SIM control. The chain-anchored revocation propagates via peer discovery. Peers stop trusting the old attestation. The identity itself is undisturbed.

This is a real, structural improvement over Signal (phone-number-anchored account), WhatsApp (same), iMessage (Apple-mediated), and every phone-number-based two-factor authentication that treats the number as the second factor.

### 4.2 No phone-number-based de-anonymization

Advertising databases, data brokers, and tracking companies that know phone numbers cannot link them to ZP identities. There is no directory, no hash-based lookup, no aggregation surface where a phone-number-based reverse lookup could succeed.

If the operator has published a phone attestation with broad visibility, that changes — the attestation is chain-visible and could be found by anyone who queries the ecosystem for it. But the operator controls attestation visibility, so this is a chosen exposure, not a default.

### 4.3 No Registration Lock complexity

Signal's Registration Lock (per their support docs and the June 2026 FBI/CISA advisory) exists specifically because phone-number re-registration is a takeover vector. ZP has nothing to "re-register on a new number" because the identity was never on a number in the first place. The complexity Signal has accumulated around phone-registration security is complexity ZP doesn't inherit.

### 4.4 Portable identity across phone changes

Operator switches carriers, changes numbers, loses their phone, gets a new phone — ZP identity persists throughout. No account recovery required, no phone-verification friction, no vulnerability window during the transition. The operator authenticates to their new device with their sovereignty provider (per encrypted storage architecture and backup/recovery landscape) and continues where they left off.

---

## Part V — The Honest Limit: Social Association Attack

The four affordances above defend against structural attacks. They do not defend against social association.

**The attack:** someone knows your phone number is X (they're in your address book). They know you're on ZP as identity Y (they've had a ZP interaction with you at Y). They now hold the association X ↔ Y in their own private records. If they publish it, or if their records are compromised, the linkage is out.

**Why this cannot be structurally defended:** ZP has no visibility into what associations peers hold in their own private records. Two facts known to a party can be linked by that party regardless of how they were acquired.

**Mitigations that reduce impact but don't eliminate:**

- **Don't publish phone attestations broadly.** Bounded to specific relationships if published at all.
- **Use bounded-space identities in sensitive contexts.** Even if your portable identity is linked to your phone number in some peer's records, your bounded identities are separate.
- **Use pattern-sharing keys for the commons.** Commons participation is not linked to your primary identity by construction.
- **Don't reveal your Genesis-derived signing identity where a bounded or purpose-scoped identity would do.** Compartmentalization is the defense.
- **The Regent helps maintain compartmentalization** (per `REGENT-COMPARTMENTALIZATION-2026-07.md`). Warnings when the operator's actions would create linkage; suggestions for which identity to use where.

The honest framing: sovereignty is real for what ZP controls; association attacks on what others hold cannot be prevented, only compartmentalized against.

---

## Part VI — Composition with Other Work

### 6.1 The ZP camera app

The ZP camera runs on a phone. The phone has a SIM, a phone number, an OS-level user account, all potentially tied to the operator's real-world identity via app store credentials. The camera app must not leak these unless the operator authorizes leakage:

- **Location is opt-in per capture** (per media provenance work). Never automatic.
- **SIM identity is not touched by the app.** The camera app does not read the phone number, does not query the SIM, does not include carrier information in provenance receipts.
- **The camera app runs against the operator's ZP identity, not the phone's identity.** Provenance receipts are signed by the operator's chain signing key, not by any device or carrier identifier.
- **OS-level app store account is not queried.** ZP does not know the operator's Apple ID or Google account.

The phone is a capable capture device but not an identity broker for ZP.

### 6.2 Backup and recovery

SMS is out for ZP backup and recovery. Per the backup and recovery landscape, no ZP recovery ceremony uses SMS as a factor. SIM swap would compromise the recovery path if it did. Recovery uses sovereignty providers (Secure Enclave, TPM, hardware wallet), Shamir shares, guardians, or the other mechanisms in that document.

Historical SMS-based backup codes (like traditional 2FA) are explicitly out. If the operator wants a backup mechanism, it must not depend on SIM control.

### 6.3 The Regent's role

The Regent is the surface that helps the operator navigate phone attestation decisions, contact-book bridging choices, and introduction ceremonies without compromising sovereignty. Per `REGENT-COMPARTMENTALIZATION-2026-07.md`:

- **Attestation decisions surfaced clearly.** "This will publish an attestation linking this identity to your phone number, with visibility [scope]. Continue?"
- **Introduction ceremonies guided.** The Regent walks the operator through incoming introduction challenges and outgoing ones.
- **Contact-book compartmentalization respected.** When surfacing contacts to the operator, the Regent respects which identity the operator is currently active in.
- **SIM-swap detection.** If the Regent detects that phone attestations are being challenged, invalidated, or actively contested, it surfaces the concern to the operator with proposed responses.

### 6.4 Peer discovery

Phone-attestation-based discovery is not part of the peer-discovery mechanism (per `PEER-DISCOVERY-AS-OUTREACH-2026-07.md`). Announces are not routed by phone number; peers do not maintain phone-based directories. Attestations that carry phone information are receipts, not routing signals.

---

## Part VII — Open Decisions

Deliberate open questions:

1. **Attestation format.** What data structure represents a phone attestation on the chain? Concretely: fields, signature scheme, revocation format, visibility scope encoding.

2. **SMS-embedded receipt format.** How are compact ZP receipts encoded for SMS transport? Payload size constraints, URL-encoded compact form, verification-at-recipient mechanics.

3. **Introduction ceremony wire format.** SMS challenge payload, QR-code representation, response protocol. Interop with existing secure messenger patterns worth investigating.

4. **Contact-book format on device.** How the operator's local contact book is structured for efficient local lookup against known ZP identities. Composes with the encrypted storage architecture.

5. **Attestation freshness.** Does a phone attestation have a natural expiry? SIM assignments change; a five-year-old attestation may be stale. Design choice: expire attestations after a period, require refresh; or leave attestations valid until explicit revocation.

6. **Regent's default posture on phone attestation.** By default, does the Regent recommend for or against attaching phone attestations? Depends on operator persona; may be per-context configurable.

---

## Part VIII — Companion Documents

- `docs/ARCHITECTURE-2026-07.md` — canonical architecture record; identity-is-a-key-not-a-location (Part VII Principle 2) is the foundational commitment this document operationalizes.
- `docs/design/REGENT-COMPARTMENTALIZATION-2026-07.md` — the Regent's role in helping operators navigate phone attestation decisions without compromising compartmentalization.
- `docs/design/BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md` — recovery mechanisms; SMS is explicitly out.
- `docs/design/ENCRYPTED-STORAGE-ARCHITECTURE-2026-07.md` — key hierarchy; phone attestations are chain receipts subject to the standard encryption architecture.
- `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md` — peer discovery mechanism; phone attestations are not part of discovery routing.
- `docs/design/MEDIA-PROVENANCE-2026-07.md` — the ZP camera app runs on phones; the composition rules that prevent phone identity from leaking into provenance receipts.

---

*Phone is a location, not an identity. The ecosystem gracefully handles the association reality without ever letting phone number become a coordinate the substrate depends on. Every phone-related affordance is optional, revocable, and scope-bounded. Sovereignty is preserved by construction, not by policy.*
