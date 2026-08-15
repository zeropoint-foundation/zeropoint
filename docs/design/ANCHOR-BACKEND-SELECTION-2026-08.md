# Anchor Backend Selection — choose the first witness by its trust root

**Document type:** Design note / decision memo. Elaborates no KEEL section; it selects an implementation behind the existing `TruthAnchor` trait and the `EXTERNAL-ANCHOR-TIER-CONTRACT`.

**Status:** Proposed 2026-08-14. No code written. Requests one operator ruling (§6).

**Date:** 2026-08-14.

**Composes with:** `EXTERNAL-ANCHOR-TIER-CONTRACT` (§5 Forbidden #5 — compact commitment only), `THREAT-MODEL-2026-08.md` (§3.4 — the scenario that needs this), `NOSTR-TRANSPORT-CONFORMANCE-2026-08.md` (§3 — the relay-classification ruling already resolved the anchoring case), `TRUST-ROOT-LOCUS-LENS-2026-08.md` (the lens this document is scored against), `DEPENDENCY-POSTURE.md` (dual-path rule).

**Attribution:** Drafted by Claude against the `zp-anchor` trait, the corpus, and the threat model. The ruling in §6 is Ken's.

---

## 1. Why this is now the blocking item

`THREAT-MODEL-2026-08.md` §3.4 works the accountability scenario — an agent drives a platform login as its operator, the platform asks "was this you" — through three deployment profiles, and the answer that distinguishes the governed substrate is *a receipt anchored where the operator cannot revise it*.

That answer is currently unavailable. `zp-anchor` is a trait with one file and no backend; the `zp-hedera` crate its doc comment references does not exist in the workspace; `README.md` showed Hedera HCS as a live component until 2026-08-14.

**The scenario that best justifies the project depends on the component least implemented.** That is the sequencing defect this memo exists to close.

## 2. What the anchor must actually do

Narrower than "put the chain on a blockchain." From `EXTERNAL-ANCHOR-TIER-CONTRACT` §5 Forbidden #5, only the **compact commitment** crosses the boundary — hash, height, signature. Never receipt bodies, actor identifiers, claim types, policy decisions or grants.

So the requirement is exactly:

> Given a chain head hash, produce evidence that **this hash existed no later than time T**, verifiable by a party that trusts neither the operator nor ZeroPoint.

Three properties, and only three:

- **Precedence.** The commitment demonstrably predates the dispute. This is the whole point; without attested time, an anchor proves only that the operator once published a hash, which the operator could do at any time including afterwards.
- **Independence.** The witness is outside the operator's control. `NOSTR-TRANSPORT-CONFORMANCE` §3 already draws this conclusion and is worth quoting, because it is counterintuitive and already ruled: *"An internal-only anchoring deployment would be worthless — a witness you control witnesses nothing."*
- **Verifiability without the witness's cooperation.** A third party must be able to check the proof later, without the anchor operator answering a query, and ideally without trusting them at all.

The trait's existing design notes are correct and constrain this usefully: anchoring is **event-driven, not scheduled** — *"the chain doesn't get 'more true' by being witnessed more often"* — and the operator chooses the backend. Both hold under every option below.

## 3. Candidates, scored by trust root

The trait's own doc comment already enumerates the field: *"Hedera HCS, Ethereum L2 calldata, Bitcoin OpenTimestamps, Ceramic streams, or a simple HTTPS timestamp authority."*

| Backend | Root of trust | Account / cost | Offline verify | Precedence |
|---|---|---|---|---|
| **OpenTimestamps** (Bitcoin) | Bitcoin proof-of-work | none / free | **Yes** — proof + block headers | ~1–6 h to confirm |
| **Sigstore Rekor** | The Rekor operator's key + witness co-signing | none / free | Partial — needs the log's key | Immediate |
| **RFC 3161 TSA** | A commercial CA | none–low | Yes, given the CA cert | Immediate |
| **Hedera HCS** | The Hedera Governing Council | account + per-message fee | No — requires querying the network | Immediate |
| **Nostr multi-relay** | None — replication only | none / free | N/A | **None** (see §4) |

**Scored against `TRUST-ROOT-LOCUS-LENS`, Hedera is the weakest candidate despite being the documented target.** That lens exists to notice when a mechanism converges with the industry while its *root* diverges, and it carries a standing finding across three sweeps: no draft or programme roots the chain in the principal's own key. Adopting a witness rooted in a governing council would be that same pattern pointed at ourselves — an institutional trust root, in the one component whose entire job is to be trustworthy to someone who does not trust us. It also costs money per commitment and requires an account, which makes the sovereign, offline, self-hosted deployment the one that cannot anchor.

**OpenTimestamps inverts every one of those.** No account, no fee, no registration. The proof is a self-contained file: a Merkle path from your hash to a Bitcoin block header. Verification needs the proof and a header chain — not the aggregator's cooperation, not its continued existence, not its honesty. If every OTS calendar server disappears tomorrow, previously issued proofs still verify. That is the strongest independence property available, and it is the one that matches what the substrate claims about itself.

Its cost is latency: a commitment is provisional until the Bitcoin transaction confirms, typically an hour or several. Under the trait's event-driven model this is nearly free — anchoring fires on audits, disputes, introductions and operator requests, none of which need a witness within seconds. And §2's requirement is *precedence*, which is a claim about the past. A proof that lands an hour late still proves the hash existed an hour ago.

## 4. What Nostr multi-relay is and is not

`NOSTR-TRANSPORT-CONFORMANCE` §3's payload table permits *"compact chain-head commitments (hash + height + signature)"* on an external relay, and it is tempting to read that as the anchor being already solved by work in flight.

It is not, and the distinction matters. Relays give **replication and witness plurality** — that document's own note that multi-relay publication *"makes withholding require collusion"* is right. What they do not give is **attested time**: a relay's `created_at` is set by the publisher and the relay may lie about when it saw an event. Nostr has no consensus timestamp and no inclusion proof.

So the two compose rather than compete:

- **OpenTimestamps** supplies precedence — *this hash existed by time T*.
- **Nostr multi-relay** supplies availability and plurality — *and here is where N independent parties can be seen to hold it*.

Publishing the OTS proof itself as a compact commitment across several external relays is strictly better than either alone, and it stays inside Forbidden #5 because an OTS proof is a hash path, carrying no chain content.

## 5. Proposed shape

**First backend: `zp-anchor-ots`**, implementing `TruthAnchor` against the OpenTimestamps protocol.

- `anchor()` submits the chain head hash to N calendar servers, stores the returned provisional proof, and upgrades it to a Bitcoin-attested proof once confirmed. `AnchorReceipt.consensus_timestamp` is the Bitcoin block time.
- `verify()` checks the Merkle path against a block header — no network call if headers are cached.
- `query()` reads locally stored proofs by time range.
- Feature-gated, off by default, per the `libp2p` precedent `NOSTR-TRANSPORT-CONFORMANCE` NT3 warns against repeating.
- Per the dual-path rule, the trait must retain at least one other viable implementation. `zp-anchor-tsa` (RFC 3161) is the natural second: immediate timestamps, different root, ~200 lines.

**Verifiable outcomes:**

- **AT1** — `zp-anchor-ots` implements `TruthAnchor` unmodified. No trait method widened.
- **AT2** — A proof verifies with the calendar servers unreachable. This is the property that distinguishes it from every account-based backend, so it is the test that matters most.
- **AT3** — Nothing but hash, height and signature crosses `anchor()`. A test asserts that a commitment carrying receipt content fails at construction, not at runtime.
- **AT4** — With the feature disabled, the workspace builds and no substrate operation changes outcome.
- **AT5** — **The §3.4 test.** Given a completed tool action, produce the receipt chain answering *which agent, under which grant, authorized by whom, expiring when* — plus an anchor proof of precedence — and verify the whole thing with the operator's keys withheld from the verifier. This is the only outcome here that tests the §1 invariant rather than a component of it, and it is `THREAT-MODEL` §7's test 7.

**Minimum slice (m0):** anchor one chain head, wait for confirmation, verify the proof offline with the network disabled. No integration with the gate, no triggers wired, no receipt family. If m0 goes badly, deleting the crate is the whole rollback.

## 6. Ruling requested

1. **Is OpenTimestamps the first backend, displacing Hedera as the documented target?** The argument is §3: Hedera's root is institutional, and a sovereignty substrate whose witness roots in a governing council has the same defect its own lens exists to detect in others. Hedera would remain a permitted backend — the trait is plural by design, and an operator who wants it should have it.
2. **Does the README's roadmap entry change accordingly?** It currently reads "◇ External Anchor — Hedera HCS is the reference target."

If the answer to (1) is no, the §5 shape holds with `zp-anchor-hedera` substituted, and AT2 becomes untestable — which is itself the argument.

## 7. Non-goals

- **Not chain storage.** Forbidden #5 stands; the commitment is a hash.
- **Not a timer.** Event-driven, per the trait's design notes.
- **Not required.** With no anchor configured the substrate operates unchanged and local chain integrity is unaffected. The anchor buys third-party verifiability, nothing else.
- **Not a currency dependency.** OTS calendar servers aggregate submissions and pay their own fees; the operator holds no wallet, no key, and no balance. Any proposal that requires the operator to hold a token reopens §6.
