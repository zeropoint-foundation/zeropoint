# Licensing and Integrity — July 2026

**Document type:** Design note. Establishes the canonical licensing posture for ZeroPoint and the substrate's contract-integrity enforcement model. Retires the pessimistic "permissive licensing permits stripping constitutional constraints" framing that appeared in earlier whitepaper drafts, replacing it with a specific three-layer posture: permissive code license, retained trademark, integrity clause on distributions claiming ZeroPoint-compatibility. The chain-invariant mechanism provides most of the structural recourse; licensing formalizes what recourse the Foundation retains where the chain cannot reach.

**Status:** Design note. Ready for iteration; open decisions marked. Whitepaper §12 threat model and whitepaper header should reference this note.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-05.

---

## Part I — The Problem, Precisely Stated

Earlier drafts treated "malicious fork" as a single threat and described permissive licensing as a defense weakness. Both framings were imprecise. Malicious-fork concerns actually decompose into three distinct threats, each with a different defense.

### 1.1 Impersonation

Someone forks the code, strips constitutional rules or modifies critical behavior, and distributes the result as "ZeroPoint" or a confusingly similar name, misleading users into thinking they're getting the real substrate.

### 1.2 Subtle subversion

Someone forks the code, keeps constitutional rules present so the fork appears conforming, and adds backdoors or vulnerabilities that let them bypass governance under specific conditions. Distributed as a tampered "compatible" build.

### 1.3 Displacement

Someone forks the code (or reimplements the architecture independently), builds a similar-looking but non-ZeroPoint substrate, and captures adoption that would otherwise have gone to the real ZeroPoint ecosystem.

### 1.4 Why the earlier framing failed

Treating these three as one problem produced the false claim that permissive licensing was a defense weakness. In fact, each threat has a distinct defense, and the primary defense against the most consequential ones is structural — the chain enforces the substrate's contract regardless of what any license permits.

---

## Part II — What the Chain Already Provides

Before adding licensing structure, name what the chain already does. Understanding structural recourse first prevents overclaiming the role of legal recourse.

### 2.1 Chain-invariant rejection

A malicious fork that strips constitutional rules produces receipts that don't include valid constitutional evaluations. When a real ZeroPoint peer verifies those receipts against the substrate invariants (per `SUPERSESSION-FRAMEWORK-2026-07.md` Part II), verification fails. The malicious fork's receipts do not parse as ZeroPoint receipts. Its peers can only interact with other peers of the same malicious fork.

The malicious fork exists as a separate network. It cannot interoperate with the ZeroPoint ecosystem because its actions cannot be recognized as substrate-conforming by the peers who care about substrate-conformance.

### 2.2 Analogy to Bitcoin

Bitcoin's code has always been permissively licensed (MIT). Anyone can fork it. Forks that don't follow Bitcoin's consensus rules produce blocks that Bitcoin nodes reject. The forks become separate networks (Bitcoin Cash, Bitcoin SV, others) with their own communities and adopters. Bitcoin's license did not prevent these forks. Bitcoin's consensus rules ensured the forks were separate networks.

ZeroPoint inherits the same pattern. The substrate contract is enforced by the invariant verification the peers perform, not by the license.

### 2.3 What structural recourse does not cover

Three cases the chain-invariant mechanism does not fully address:

- **Impersonation attacks that succeed before adopters check the chain.** A user who downloads a malicious build and thinks they're running ZeroPoint may be harmed before they ever attempt to interact with real ZeroPoint peers.
- **Tampered builds that appear conforming.** If constitutional rules are present but subtly bypassable, the invariant checks may pass while the substrate is compromised.
- **Naming and reputational damage.** Even if a malicious fork cannot interoperate, its existence under confusing branding damages ZeroPoint's reputation and adopters' ability to distinguish real from fake.

These are the specific gaps that licensing and trademark structure address.

---

## Part III — The Three-Layer Licensing Posture

The substrate's licensing posture has three composing layers, each with distinct scope and enforcement mechanism.

### 3.1 Layer 1: Code license — permissive (MIT / Apache-2.0 dual)

The substrate code ships under a permissive MIT/Apache-2.0 dual license. This preserves:

- **Sovereignty.** Operators can modify their own instance without restriction.
- **Forkability.** Anyone can fork, modify, and redistribute the code under their own name.
- **Ecosystem contribution.** Contributors can offer code without navigating restrictive licensing.
- **Downstream integration.** Third parties can integrate substrate components into their own systems.

Permissive licensing is a non-negotiable property. The substrate's philosophical foundation requires it. What earlier framings treated as a defense weakness is actually a load-bearing feature.

### 3.2 Layer 2: Trademark policy — retained

The Foundation retains trademarks on:

- "ZeroPoint" (the name)
- The ZeroPoint logo and visual identity marks
- "ZeroPoint Open Foundation" and Foundation-associated marks
- Related word marks that could cause consumer confusion ("Zero Point," "ZP" in substrate context, etc.)

Trademark policy allows the Foundation to take action against distributions that use "ZeroPoint" or related marks in ways that could mislead adopters — calling a non-conforming fork "ZeroPoint," or using the marks to imply compliance that doesn't exist. Standard trademark grounds, applied narrowly to actual naming confusion.

This is analogous to how Firefox / Chromium / Signal manage code licensing. The code is open; the name is protected. Legitimate forks under different names are welcomed and expected.

### 3.3 Layer 3: Integrity clause — on distributions claiming compatibility

Distributions that self-identify as ZeroPoint-compatible are subject to an integrity clause. In substance:

*"Distributions that identify themselves as compatible with the ZeroPoint substrate contract must preserve the invariants specified in `SUPERSESSION-FRAMEWORK-2026-07.md` Part II. Distributions that violate those invariants may not represent themselves as ZeroPoint-compatible."*

Enforcement is layered but structural first:

- **Structural (primary).** Non-conforming distributions produce receipts that fail invariant verification at the peer level. The substrate contract enforces itself; this is where the real enforcement happens.
- **Test suite (objective).** The invariant test suite (per `SUPERSESSION-FRAMEWORK-2026-07.md` Part X open decision 4) provides a chain-anchored, objectively-runnable basis for determining compliance. Anyone can run it. The Foundation does not certify compliance; the test suite is the standard.
- **Legal (narrow backstop).** A distribution that makes false claims about ZeroPoint-compatibility is subject to Foundation action on trademark and misrepresentation grounds. This is a narrow backstop, not the primary defense.

The integrity clause is not a license restriction on code use. It is a representation clause: what you say about your distribution's relationship to the substrate contract. Self-attestation is the default posture — anyone can claim compatibility, anyone can verify the claim via the test suite, and the Foundation acts only when someone makes materially false claims that could confuse adopters.

---

## Part IV — What Each Layer Does and Does Not Do

Being precise about scope prevents overclaiming.

### 4.1 The code license (MIT/Apache-2.0)

**Does:**
- Permits use, modification, distribution of source and binaries.
- Requires attribution and license notice.
- Provides patent grant (Apache 2.0 side).
- Disclaims warranty.

**Does not:**
- Restrict operator modifications of their own instance.
- Restrict fork creation.
- Prohibit stripping constitutional rules from a fork.
- Prevent redistribution under different names.

### 4.2 The trademark policy

**Does:**
- Prevent unauthorized use of "ZeroPoint" and related marks.
- Provide grounds for takedown of impersonating distributions.
- Give the Foundation standing to defend the ecosystem's naming integrity.

**Does not:**
- Restrict what operators do inside their own instances.
- Prevent forks under different names.
- Restrict discussion, review, criticism, or reference to ZeroPoint.
- Prevent legitimate compatibility statements ("compatible with ZeroPoint chain format").

### 4.3 The integrity clause

**Does:**
- Establish a distributed test suite as the basis for compatibility claims.
- Provide Foundation legal recourse against distributions that materially misrepresent compliance and cause harm.
- Compose with structural chain-invariant rejection.

**Does not:**
- Restrict code modification.
- Restrict distribution under non-ZeroPoint names.
- Require Foundation approval for compatibility claims (self-attestation, structurally verifiable).
- Constrain operator behavior at all.

### 4.4 What none of these layers do

None of the three layers give the Foundation authority over operators. Operator sovereignty is preserved throughout. The Foundation's recourse extends only to distributions and representations, not to operator behavior.

---

## Part V — Foundation Recourse, Bounded

The Foundation retains narrow legal standing — trademark misuse and false compatibility claims only. Everything else about maintaining the substrate contract happens structurally at the chain layer or objectively via the invariant test suite.

### 5.1 What the Foundation may act on

Two categories:

- **Trademark misuse.** Distributions using "ZeroPoint" or related marks in ways that mislead adopters — calling a non-conforming fork "ZeroPoint," using the marks to imply compliance that doesn't exist. Standard trademark grounds, applied narrowly to actual naming confusion.
- **False compatibility claims.** Distributions that materially misrepresent their substrate-contract compliance in ways that could confuse adopters. Standard misrepresentation grounds, backed by the objective invariant test suite as the basis for what compliance means.

That is the complete scope of Foundation legal recourse. Nothing else.

### 5.2 What the Foundation may not act on

- **Operator modifications** of their own instance. Operator sovereignty is inviolable.
- **Legitimate forks under different names.** Any operator or organization can build on ZeroPoint's ideas and code under different naming without Foundation involvement.
- **Criticism, review, comparison.** Standard First Amendment and fair-use protections apply.
- **Non-conforming implementations that do not claim ZeroPoint-compatibility.** A substrate that borrows ZeroPoint's architecture but calls itself something else is engaging in legitimate ecosystem participation.
- **Adopter choices.** Adopters can choose to use any substrate they want.

### 5.3 What the Foundation is not

Naming this explicitly, because certification authorities and standards bodies tend to accumulate power in ways their founding charters didn't anticipate:

- **Not a certification authority.** The Foundation does not certify distributions as conformant. Conformance is objectively checkable via the invariant test suite; anyone can run it. The Foundation acts on trademark misuse and false compatibility claims; it does not bless or withhold blessing for specific implementations.
- **Not a standards body.** The Foundation is one participant in the ecosystem's evolution via the ZEP process (per `SUPERSESSION-FRAMEWORK-2026-07.md`). It does not have unique authority to set standards. Substrate invariants are chain-anchored and community-verified.
- **Not a gatekeeper.** Contribution, distribution, and forking (under other names) require no Foundation approval.

If the ecosystem ever finds it needs a formal certification or standards body — for regulatory adoption in specific industries, for interoperability guarantees in specific contexts — that body should be a separate entity, deliberately not controlled by the Foundation or by any single individual. The Foundation's structural design does not equip it to be a certification body, and any attempt to make it one would compromise both the Foundation's peer status in the ecosystem and the ecosystem's broader trust in objective substrate verification.

### 5.4 The Foundation's actions themselves are governed

Because the Foundation is a peer in the ecosystem (per `COMMUNITY-COORDINATION-ON-ZEROPOINT-2026-07.md` Part VI), its legal actions are subject to the same transparency and community accountability as any other Foundation activity. Legal actions taken by the Foundation are chain-anchored as receipts on the Foundation's own chain, discoverable by any operator who cares to look.

The Foundation cannot secretly pursue takedowns or restrictions. Every action is visible.

---

## Part VI — Composition with Chain Enforcement

The licensing posture composes with several substrate mechanisms that provide structural enforcement.

### 6.1 Software integrity attestation

Per `SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md`, distributions attest to their build integrity through chain-anchored release receipts and runtime attestation. Tampered builds cannot produce valid attestations because their hash does not match the release chain. This addresses the "subtle subversion" threat class from §1.2.

### 6.2 Invariant test suite

Per `SUPERSESSION-FRAMEWORK-2026-07.md`, the invariant list is a chain-anchored artifact. The invariant test suite (open decision) provides an objective basis for evaluating compatibility claims. Distributions claiming ZeroPoint-compatibility can be tested; non-conforming distributions fail objectively-checkable tests.

### 6.3 Reference implementation as one option among many

Per `SUPERSESSION-FRAMEWORK-2026-07.md` Part VI, the Foundation's reference implementation is one adopted set among possible sets. Operators can run alternative implementations that preserve the invariants. The reference implementation is "reference" because the Foundation supports it, not because it is the only conforming implementation.

Distributions that preserve the invariants but are not the reference implementation are legitimate. Distributions that fail the invariants are not ZeroPoint, regardless of what they call themselves.

### 6.4 Trademark as clarity, not gatekeeping

The trademark's purpose is to prevent user confusion, not to gatekeep contribution. Multiple parties can be authorized to use "ZeroPoint" in specific contexts: contributors describing their contributions, adopters describing their implementations, communities describing their participation. What's prevented is the specific case of misrepresentation.

---

## Part VII — Adversarial Scenarios Revisited

Applying the three-layer posture to the specific threats named in Part I.

### 7.1 Impersonation

**Attack:** Malicious actor forks, strips constitutional rules, releases as "ZeroPoint."

**Defense:**
- Trademark takedown against the appropriated name.
- Chain-invariant rejection prevents interoperation with real ZeroPoint peers.
- Foundation-issued advisory alerting adopters to the impersonation.
- Community reputation dynamics identify and mark the malicious fork.

**Residual risk:** Users who download the malicious build before takedown may be harmed. Legal takedown speed matters.

### 7.2 Subtle subversion

**Attack:** Malicious actor forks, keeps constitutional rules present but adds backdoors, distributes as tampered "compatible" build.

**Defense:**
- Chain-anchored release receipts require reproducible builds; tampered builds don't match the release chain.
- Runtime attestation stack verifies what the substrate actually running is.
- Independent verification of releases by community members catches subtle deviations.
- Integrity clause provides legal recourse against distribution that materially misrepresents its substrate compliance.

**Residual risk:** Very sophisticated attacks may evade both structural and legal defenses for a time. Detection is best-effort. Reputation dynamics eventually catch what technical defenses miss.

### 7.3 Displacement

**Attack:** Alternative substrate captures adoption via similar architecture with different guarantees.

**Defense:**
- This is not really an attack. Alternative substrates are legitimate ecosystem participants.
- Trademark prevents specific naming confusion.
- Beyond that, the market and adopter judgment decide.

**Not a residual risk.** Displacement by better alternatives is how ecosystems evolve. If someone builds a substrate that adopters prefer, that's a signal, not a threat.

### 7.4 Naming-adjacent confusion

**Attack:** Distribution uses names like "ZeroPointAI," "ZP-Enhanced," "Zeropoint Pro" to confuse adopters without directly using the "ZeroPoint" trademark.

**Defense:** Trademark policy extends to confusingly-similar naming. Foundation retains standing to act against distributions structured to cause consumer confusion.

**Residual risk:** Aggressive naming-adjacent branding may sometimes require case-by-case adjudication. Case law from established trademark practice provides precedent.

---

## Part VIII — Ecosystem Properties Preserved

Beyond the Foundation-authority bounds specified in Part V, the three-layer posture preserves ecosystem properties that make ZeroPoint what it is:

- **Forkability.** The code license permits forks. Only distributions claiming to be the reference implementation face additional constraints.
- **No gatekeeping.** Contribution requires no Foundation approval. Proposals, patches, alternative implementations, and community forks are all legitimate participation.
- **No lock-in.** Operators can leave the ZeroPoint ecosystem and take their identity, chain history, and derived state with them.

---

## Part IX — What This Enables

The three-layer posture enables things the earlier framing did not.

- **Adopter clarity.** Adopters can verify they are getting the real substrate via chain-anchored release receipts, marked distributions, and objective invariant tests. "Is this really ZeroPoint?" has a checkable answer.
- **Foundation recourse against genuine bad actors.** When a malicious actor tries to impersonate or materially misrepresent, the Foundation can act — legally, structurally, and reputationally.
- **Ecosystem defense against reputation attacks.** A malicious fork can no longer damage ZeroPoint's reputation just by existing under confusingly-similar branding.
- **Regulatory-adopter clarity.** Adopters who need to demonstrate their substrate is what they claim have the invariant test suite and chain-anchored release receipts to point at. The evidence is objective and Foundation-independent.
- **Reference implementation credibility.** The Foundation's reference release is distinguishable from tampered clones by the release chain of trust, not by trust in the Foundation alone.

---

## Part X — Open Design Decisions

1. **Trademark portfolio scope.** Specific marks to register, jurisdictions to file in, priorities for enforcement. Standard IP counsel territory.

2. **Integrity clause exact wording.** The one-paragraph representation-of-compliance clause needs precise legal drafting. Should read like §3.3 in substance but be enforceable in relevant jurisdictions.

3. **Jurisdiction and enforcement strategy.** Where the Foundation files, which jurisdictions it can practically enforce in, what the escalation path looks like.

4. **Fork identification and labeling conventions.** What labeling non-conforming forks should adopt to be transparent about their status ("ZeroPoint-derived, not ZeroPoint-compatible" or similar). Community norm rather than legal requirement.

5. **Invariant test suite maintenance model.** Who maintains the test suite, how updates are proposed and approved (a Meta ZEP, per the supersession framework).

6. **Compatibility self-attestation format.** How a conforming distribution attests to its compatibility — chain-anchored declaration, test-suite results receipt, or both.

7. **Foundation legal-action governance.** Threshold for the Foundation to initiate legal action, transparency requirements, community input mechanisms for contested cases.

8. **Community-fork blessing pattern.** Whether the Foundation issues explicit endorsements for community forks that preserve the invariants and represent themselves clearly, or whether such endorsement itself becomes gatekeeping.

9. **Documentation of adopter-facing verification.** The chain-anchored release verification story needs adopter-facing documentation so users know how to check what they're running.

10. **International enforcement realities.** Trademark and legal recourse have real jurisdictional limits. What operators in jurisdictions where the Foundation has limited enforcement capability can do to verify what they're running.

---

## Part XI — Companion Documents

- `docs/ARCHITECTURE-2026-07.md` — canonical architecture record; principle 8 (one canonical path per substrate concern) informs why the substrate contract is precisely one thing that can be either preserved or violated.
- `docs/whitepaper-v9.md` — §12 (Threat Model) threat rows for security theater and surveillance co-option should be updated to reflect the three-layer defense rather than treating permissive licensing as a defense weakness. Whitepaper header should note the trademark and integrity clause alongside the code license.
- `docs/design/SUPERSESSION-FRAMEWORK-2026-07.md` — the invariant list (Part II) is what the integrity clause enforces preservation of. The invariant test suite (open decision) is the objective basis for compatibility determination.
- `docs/design/SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md` — the build attestation stack that catches tampered releases.
- `docs/design/COMMUNITY-COORDINATION-ON-ZEROPOINT-2026-07.md` — the community-and-Foundation relationship structure that this licensing posture composes with.

---

## Part XII — Closing

The Foundation's role is protecting the name and preventing false claims about compatibility. It is not defending the substrate contract in some broader sense — the substrate defends its own contract structurally at the chain layer, and the invariant test suite provides the objective standard anyone can run.

The earlier framing — "permissive licensing permits stripping constraints from a fork" — treated a load-bearing property (permissive licensing) as a defense weakness, when in fact the primary defense against constraint-stripping is structural (chain-invariant rejection), the primary defense against impersonation is legal (trademark), and the primary defense against subtle subversion is technical (attestation). Each is precise; each is bounded; each preserves what it must preserve.

The Foundation is not a certification authority, not a standards body, and not a gatekeeper. It defends the name and acts on false compatibility claims — nothing more. If the ecosystem ever needs certification or standards infrastructure, that infrastructure should be built as a separate entity, deliberately not controlled by the Foundation or by any single individual.

---

*Permissive code license, retained trademark, integrity clause on distribution-level compatibility claims. Sovereignty preserved throughout. Chain enforcement is the primary defense; the invariant test suite is the objective standard; legal recourse is a narrow backstop for trademark misuse and false compatibility claims. The Foundation is not a certification authority, not a standards body, and not a gatekeeper — its role is to defend the name and act on false claims, nothing more. Malicious forks that strip the substrate contract exist as separate networks by construction and cannot interoperate with the real ZeroPoint ecosystem. The framing that treated permissive licensing as a weakness is retired.*
