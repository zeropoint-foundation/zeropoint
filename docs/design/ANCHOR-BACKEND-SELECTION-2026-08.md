# Anchor Backend Selection — a floor that always works, an escalation that answers harder questions

**Document type:** Design note / decision memo. Elaborates no KEEL section; it selects implementations behind the existing `TruthAnchor` trait and the `EXTERNAL-ANCHOR-TIER-CONTRACT`.

**Status:** Proposed 2026-08-14. **Revision 2, same day** — revision 1 posed a false choice between backends and got two supporting facts wrong; see §7. **§6.1 resolved 2026-08-14 by operator ruling: OTS is the default-enabled floor, Hedera remains supported.** The floor is built — `zp-anchor-ots` landed the same day at `2a7d0b3`, compiling and tested, with AT2 explicitly not yet met and the crate saying so. **§6.3 closed the same day, not pursued** — commitments are not routed through Nostr relays, and the resulting suppression gap is recorded as a stated limitation in `THREAT-MODEL-2026-08.md` §5. **No open rulings remain in this document.**

**Date:** 2026-08-14.

**Composes with:** `EXTERNAL-ANCHOR-TIER-CONTRACT` (§5 Forbidden #5 — compact commitment only), `THREAT-MODEL-2026-08.md` (§3.4 — the scenario that needs this), `NOSTR-TRANSPORT-CONFORMANCE-2026-08.md` (§3 — the relay-classification ruling, and an open question this document raises against it), `TRUST-ROOT-LOCUS-LENS-2026-08.md`, `DEPENDENCY-POSTURE.md` (dual-path rule).

**Attribution:** Drafted by Claude against the `zp-anchor` trait, the corpus, and primary sources cited inline. The rulings in §6 are Ken's.

---

## 1. Why this is now the blocking item

`THREAT-MODEL-2026-08.md` §3.4 works the accountability scenario — an agent drives a platform login as its operator, the platform asks "was this you" — through three deployment profiles, and the answer distinguishing the governed substrate is *a receipt anchored where the operator cannot revise it*.

That answer is currently unavailable. `zp-anchor` is a trait with one file and no backend; the `zp-hedera` crate its doc references does not exist in the workspace.

**The scenario that best justifies the project depends on the component least implemented.** That is the sequencing defect this memo closes.

## 2. What the anchor must actually do

Narrower than "put the chain on a blockchain." Per `EXTERNAL-ANCHOR-TIER-CONTRACT` §5 Forbidden #5, only the **compact commitment** crosses the boundary — hash, height, signature. Never receipt bodies, actor identifiers, claim types, policy decisions or grants.

So the requirement is:

> Given a chain head hash, produce evidence that **this hash existed no later than time T**, verifiable by a party that trusts neither the operator nor ZeroPoint.

Four properties matter, and revision 1 only named three:

- **Precedence.** The commitment demonstrably predates the dispute.
- **Independence.** The witness is outside operator control. `NOSTR-TRANSPORT-CONFORMANCE` §3 already ruled on this: *"an internal-only anchoring deployment would be worthless — a witness you control witnesses nothing."*
- **Verifiability without the witness's cooperation.** A third party can check the proof later without the anchor operator answering a query.
- **Non-suppressibility.** *(New in revision 2, and the property that changes the conclusion.)* A third party can establish that a commitment exists **without the operator's cooperation.** These last two are not the same property, and no single backend has both.

The trait's existing design notes constrain this usefully and hold under every option: anchoring is **event-driven, not scheduled** — *"the chain doesn't get 'more true' by being witnessed more often"* — and **the operator chooses the backend** (design principle #3).

## 3. The two serious candidates, scored honestly

The trait's doc comment already enumerates the field: *"Hedera HCS, Ethereum L2 calldata, Bitcoin OpenTimestamps, Ceramic streams, or a simple HTTPS timestamp authority."* Two are serious for this substrate.

| | OpenTimestamps | Hedera HCS |
|---|---|---|
| Trust root | Bitcoin proof-of-work | Hedera Governing Council |
| Account required | none | account + funded HBAR balance |
| Cost per commitment | none | **$0.0008** (raised 8× from $0.0001, Jan 2026) |
| Time resolution | **±2–3 hours** (Bitcoin attestation) | seconds, exact consensus timestamp |
| Ordering between commitments | none | total order within a topic |
| Verify offline | **yes**, once upgraded | no — requires querying the network |
| Survives its infrastructure dying | **yes**, upgraded proofs verify against block headers forever | no |
| Third party can confirm **without operator** | **no** — the proof is a file the operator holds | **yes**, via mirror nodes |

### 3.1 Hedera's case, stated at full strength

**Suppression resistance is the strongest argument, and revision 1 missed it.** An OTS proof is a file *you* possess. In a dispute where you are the party being questioned, a witness only you hold is not forgeable — but it is losable, and it is withholdable. Nothing compels you to produce it. An HCS topic is queryable by a third party through mirror nodes: the platform can confirm a commitment existed at a time **without your cooperation**. For an adversary class defined as "a platform deciding whether to believe you" (`THREAT-MODEL` A4), that asymmetry is the whole game.

**Precise time and ordering.** Seconds of finality with an exact timestamp, and a total order across a topic. OTS gives a ±2–3 hour window per hash and no relation between separate proofs. If a dispute turns on sequence — this grant preceded that action — OTS cannot answer and Hedera can.

**Legibility.** In a compliance conversation, "anchored to Hedera Consensus Service" is a recognised answer. "A Bitcoin calendar aggregation proof" requires a paragraph of explanation to someone who will not read it.

**Cost is not an objection.** Revision 1 implied it was; at $0.0008 per message and event-driven volume, this is single-digit dollars a year. The real burden is needing a funded account — a custody and operations question, not a financial one.

### 3.2 Where Hedera's case is thinner than it looks

The queryable record is a **hash**. A third party learns existence and time, not content — they still need the operator to supply the receipt that hashes to it. Hedera removes the operator's ability to suppress *that something happened*; it does not remove the ability to withhold *what*.

And the funded-account requirement bites precisely where this project claims to live: an air-gapped, self-hosted, or unbanked deployment cannot hold a funded HBAR balance, and therefore cannot anchor at all. Scored against `TRUST-ROOT-LOCUS-LENS`, the governing-council root also remains that lens's standing finding — mechanism converges, root does not — pointed at ourselves.

### 3.3 Where OTS is weaker than revision 1 claimed

Stated plainly, because revision 1 overstated it:

- **Durability applies to *upgraded* proofs only.** Peter Todd's own account is precise: a proof is self-validating and easy to mirror *after* `ots upgrade` pulls the Bitcoin attestation. Before that, an incomplete timestamp still depends on the calendar server. Revision 1's "survives everything" described the end state, not the lifecycle.
- **±2–3 hour resolution.** Fine for "did this precede a complaint filed a week later." Useless for ordering two actions an hour apart.
- **Custody is the operator's problem**, which is what makes suppression possible.

What survives unchanged is the part that matters for a floor: *"the worst an aggregation server can do is go offline, an inconvenience. The aggregation system **can't** produce a fake timestamp, because it's Bitcoin, not the aggregation system, that proves the validity."*

### 3.4 The reframe

Revision 1 asked which backend displaces the other. That was the wrong question — the trait is plural by design and its third design principle is that the operator chooses. These two fail differently rather than competing:

- **OTS is the floor.** No account, no balance, no institutional root, works in every deployment including the air-gapped one, costs nothing to leave enabled.
- **Hedera is the escalation.** Precise time, ordering, and third-party queryability — the properties that answer the harder half of §3.4, for deployments that can hold an account.

Keeping Hedera is not a concession on this reading. It is the backend that answers the suppression question, and nothing else in the field does.

### 3.5 Nostr relays are not a third option

`NOSTR-TRANSPORT-CONFORMANCE` §3's payload table permits *"compact chain-head commitments (hash + height + signature)"* on external relays, which invites reading the anchor as already solved by work in flight. It is not.

Relays supply **replication and witness plurality** — that document's note that multi-relay publication *"makes withholding require collusion"* is correct. They do not supply **attested time**: `created_at` is publisher-set and a relay may lie about when it saw an event.

They do bear on **suppression**, which is the gap in the OTS floor: publishing OTS proofs across several external relays would let a third party observe that a commitment exists without the operator producing it, recovering much of what Hedera offers without an account.

**That route was considered and declined — §6.3, closed 2026-08-14.** This section originally raised it as an open question against `NOSTR-TRANSPORT-CONFORMANCE`, on the grounds that §3.2's ephemerality ruling is scoped to cross-sovereign *kinship* payloads while §3's table permits chain-head commitments on external relays without saying whether those must be ephemeral too.

The question is not answered but **dissolved**: commitments are not routed through relays at all, so the ambiguity in that table never has to be resolved and §3.2 keeps a single principle with no exception carved into it. The deciding cost was that `AnchorTrigger` is event-driven, so a persisted commitment history would disclose *when the operator was in dispute* — a worse leak than the chain-growth-rate one this document set out to avoid, and one that survives every mitigation available, because the leak is in the timing and timing is the point.

**Anchoring and Nostr transport are therefore independent concerns, and this document makes no claim on that one.** The suppression gap is real, accepted, and recorded in `THREAT-MODEL-2026-08.md` §5. Reopening conditions are in §6.3.

## 4. Proposed shape

**Floor: `zp-anchor-ots`.** Submits the chain head hash to N calendar servers, stores the provisional proof, upgrades it to a Bitcoin-attested proof once confirmed. `verify()` replays the commitment operations against a block header, no network call with headers cached. Feature-gated; intended to be the default-enabled backend because enabling it requires nothing of the operator.

**Escalation: `zp-anchor-hedera`.** Implements the same trait against HCS with an operator-configured topic and account. Enabled by configuration, never by default, because it requires a funded balance the operator must consciously provision.

Both behind the existing trait, unmodified. Per the dual-path rule, having two real implementations is itself the point — `DEPENDENCY-POSTURE`'s *"hedged architecturally; not yet hedged in code"* is the drift this avoids.

**Verifiable outcomes:**

- **AT1** — both crates implement `TruthAnchor` unmodified. No trait method widened.
- **AT2** — *(rescoped in revision 2)* **an upgraded OTS proof verifies with every calendar server unreachable.** Revision 1 treated this as a universal discriminator, which was unfair — it is a property of the floor, and the reason the floor is the floor. It is not a defect in Hedera that it fails a test defined around offline verification.
- **AT3** — **the suppression test, and Hedera's counterpart to AT2.** A third party, given only a topic ID and a hash, confirms the commitment's existence and time through a mirror node with the operator offline.
- **AT4** — nothing but hash, height and signature crosses `anchor()` in either backend. A test asserts a commitment carrying receipt content fails at construction, not at runtime.
- **AT5** — with both features disabled, the workspace builds and no substrate operation changes outcome.
- **AT6** — **the §3.4 test.** Given a completed tool action, produce the receipt chain answering *which agent, under which grant, authorized by whom, expiring when* — plus an anchor proof of precedence — and verify the whole thing with the operator's keys withheld from the verifier. This is `THREAT-MODEL` §7's test 7, and the only outcome that tests the invariant rather than a component.

**Minimum slice (m0):** anchor one chain head via OTS, wait for confirmation, verify the proof offline with the network disabled. No gate integration, no triggers wired, no receipt family. Deleting the crate is the whole rollback. Hedera follows at m1, when AT3 becomes testable.

## 5. Non-goals

- **Not chain storage.** Forbidden #5 stands; the commitment is a hash.
- **Not a timer.** Event-driven, per the trait's design notes.
- **Not required.** With no anchor configured the substrate operates unchanged and local chain integrity is unaffected.
- **The floor must not require a funded balance.** *(Revised — revision 1 stated this as a blanket refusal of any token dependency, which would have excluded Hedera entirely and was the error that produced the false choice.)* The requirement is not that no backend may need funding; it is that the **default** must not, so that a deployment with no account still anchors. This is the reason for the floor/escalation split rather than an argument against Hedera.

## 6. Rulings

### 6.1 — RESOLVED 2026-08-14 by operator ruling

> **OpenTimestamps is the default-enabled floor. Hedera remains supported as a configured backend.**

Operator ruling, 2026-08-14. This adopts §3.4's floor/escalation shape in full: neither backend displaces the other, and the trait's third design principle — the operator chooses — is preserved rather than pre-empted.

What the ruling settles, stated so a later reader does not have to infer it:

- `zp-anchor-ots` ships **enabled by default**, because enabling it asks nothing of the operator. A deployment with no account, no balance and no network egress beyond HTTP still anchors.
- `zp-anchor-hedera` is **supported and never default**, because it requires a funded balance the operator must consciously provision. Its purpose is the property OTS structurally lacks — a third party confirming a commitment exists without the operator producing it (AT3).
- **Neither is deprecated.** A deployment may run both; they answer different questions, and running both is the strongest posture rather than a redundant one.

### 6.2 — Settled by events, not by ruling

Build order resolved itself: `zp-anchor-ots` landed 2026-08-14 (`2a7d0b3`), so OTS is first by construction. Recorded here rather than left as an open question, since an open position that events have already closed is the kind of stale entry `IMPROVEMENT-LOOP-DISCIPLINE` exists to prevent.

`zp-anchor-hedera` is unbuilt and unscheduled. Its shape is specified in §4.

### 6.3 — CLOSED 2026-08-14, not pursued

The question was whether a chain-head commitment may persist on an external Nostr relay, which would let relay publication close the suppression gap in the floor without requiring an account. **It is closed by deciding not to route commitments through relays at all**, leaving `NOSTR-TRANSPORT-CONFORMANCE` §3.2's ephemerality ruling untouched and unamended.

Four reasons, recorded because a closed question with no reasoning reopens itself:

1. **Nothing was blocked by it.** No deployment has a suppression problem. The floor works and Hedera is the specified answer for anyone who needs one.
2. **The question was generated by this document, not by a need.** Anchoring and Nostr transport are adjacent, and adjacency was mistaken for a reason to couple them. Left alone they stay two independent concerns, which is what they are.
3. **A significant cost surfaced late.** Because `AnchorTrigger` is event-driven — `DisputeEvidence`, `GovernanceEvent`, `CrossMeshIntroduction` — a persisted commitment history discloses **when the operator was in dispute**, not merely how fast the chain grew. Dropping `chain_sequence` does not touch it, since the leak is in the timing and timing is irreducible when publication is the point. That is materially worse than the announce enumeration surface `NOSTR-TRANSPORT-CONFORMANCE` §4 already argues against, and it was found after the amendment was drafted.
4. **The asymmetry favours waiting.** Adding relay publication later is cheap. Un-amending a clean invariant after it has been carved up is not.

**Consequence, recorded rather than hidden:** the default anchor floor has no suppression resistance. This is now a stated limitation in `THREAT-MODEL-2026-08.md` §5 rather than an open question, which is the correct home for a known and accepted property.

**If this reopens**, the trigger is a real deployment that needs a third party to confirm a commitment without the operator's cooperation *and* cannot hold a funded account. Note that a permanent public medium — the operator's own site, a git repo, a transparency log — closes the gap without any ruling about Nostr, and should be weighed before the transport document is amended. `NOSTR-TRANSPORT-CONFORMANCE-2026-08-PROPOSED-EDITS.md` is parked, not withdrawn, and holds the drafted mechanics.

## 7. What revision 1 got wrong

Recorded rather than silently edited, because two of the three are factual.

- **Cost was cited as a barrier.** It is not. $0.0008 per message, raised 8× in January 2026 from $0.0001, at event-driven volume. The real burden is account custody, which is a different and weaker argument than the one made.
- **OTS durability was overstated.** "Verifies offline, survives everything" is true of upgraded proofs. Incomplete timestamps depend on the calendar until upgraded, and Bitcoin's attestation is accurate only to within two or three hours — a limitation revision 1 did not mention at all.
- **The framing was a false choice.** Displacement was never the question; the trait is plural and the operator chooses. Revision 1 scored Hedera against criteria drawn from OTS's strengths and concluded, unsurprisingly, that OTS won. Suppression resistance — the property Hedera has and OTS lacks — went unnamed, and it is the property §3.4 most depends on.
