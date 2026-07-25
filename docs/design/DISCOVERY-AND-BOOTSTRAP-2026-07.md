# Discovery and Bootstrap

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), Part VII (Peer-Verification Contract), §III.1 (Decision D — collectives are compositional), §III.23 (coordination not oversight). Specifies how sovereigns discover each other and bootstrap into the mesh, using the existing internet as the primary discovery substrate. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `PEER-TRUST-ANCHOR-2026-07.md` (discovery precedes trust-anchor grants), `SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md` (kinship declarations follow discovery + trust anchor), `COPRESENCE-BEACON-PROTOCOL-2026-07.md` (private-mode discovery via short-range signaling; rendezvous signals extend beacon types), `DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md` (reputation flow through discovery layer), `SHARED-SPACE-SENSING-ETIQUETTE-2026-07.md` (bystander signaling composes with private-mode discoverability), `SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md` (discovery entries attest substrate integrity), `PEER-DISCOVERY-AS-OUTREACH-2026-07.md` (earlier peer-discovery framework superseded and elaborated).

## Framing

Every peer-to-peer trust system faces the bootstrap problem: how does a new sovereign find their first peers? Substrate cannot presume centralized identity registry (that's the shape we reject). It cannot presume physical-world introduction for every peer (that doesn't scale to mesh operations). It cannot presume ambient always-on discovery beacons (that violates coordination-not-oversight discipline). The pragmatic answer is: **use the existing internet as the primary discovery layer, layered with substrate discipline for trust chain integrity.**

The substrate does not replace DNS, HTTP, social platforms, or the routing infrastructure they operate on. It uses them. What the substrate adds is the trust discipline on top: entries in public directories are Genesis-signed and commons-reputation-tracked; seed nodes for bootstrap are federated and reputation-weighted; vouching receipts chain-anchor introductions; rendezvous signals enable time-bounded intentional discoverability; direct address exchange handles the "friend of a friend" case. Five layers of discovery, each with its own trust properties, composing into a mesh that grows organically without either centralization or fragmentation.

Three properties frame the discipline:

1. **Discovery layers are chosen per interaction, not enforced universally.** Some peers you meet through their public directory listing; some through a mutual friend's vouching; some through a rendezvous signal at a conference; some through direct address exchange over a private channel. Substrate supports all five layers; operator judgment picks which layer fits each new relationship.
2. **Every discovery-layer artifact is Genesis-signed by its emitter.** Directory listings, vouching receipts, rendezvous signals, and introduction claims all carry the emitter's Genesis signature. Forgery requires Genesis compromise. Substrate's trust chain extends into the discovery surface without exception.
3. **Discovery does not equal trust.** Finding a peer is not the same as trusting them. Discovery layer produces candidate peers; PEER-TRUST-ANCHOR discipline governs whether operator grants any admission surface; KINSHIP-PRIMITIVES discipline governs relational depth. Discovery is the outermost layer of the trust onion; trust anchor is inner; kinship is innermost.

## The five-layer discovery model

Each layer serves different discovery use cases and carries different trust properties.

### Layer 1 — Public directory listings

Sovereigns publish presence as a public directory listing under their own domain, in a well-known location, or in a community-hosted directory. Analogous to how professional profiles work on the current internet, adapted to substrate trust discipline.

**Format:**
- Well-known URI at operator's website: `https://<operator-domain>/.well-known/zeropoint/sovereign.json`
- Or community directory: `https://directory.example/sovereigns/<sovereign_id>`
- Or DNS TXT records: `_zp.<operator-domain>.` publishing signed presence indicator

**Content:**
- Sovereign identifier (Genesis public key)
- Optional display name (operator-declared)
- Contact channels (email, physical mail, social profile references)
- Substrate integrity attestation (per SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md)
- Vouching-permitted flag (operator declares whether they accept vouching-based introductions)
- Optional operator-declared context (roles, interests, community affiliations)
- Genesis-signed timestamp

Listing is refreshed periodically; unrefreshed listings decay (are treated as stale by inquirers per operator's declared staleness threshold).

**Trust properties:**
- Cheap to publish, easy to discover
- Signature-verifiable — Genesis-signed content prevents impersonation
- Public — anyone with the URL can view; no discovery gate
- Reputation-flowed via DISTRIBUTED-KNOWLEDGE-COMMONS — commons hosts reputation signals about specific sovereigns' public listings

**Attacks:**
- Sybil attacks (attacker creates many fake sovereigns): mitigated by reputation flow and vouching layer; new listings have low default trust
- Impersonation: prevented by Genesis-signed listings; unsigned or forge-signed listings are structurally invalid
- Poisoning (community directory is compromised): mitigated by federated directories, cross-verification, commons reputation on directory providers themselves

### Layer 2 — Seed nodes and federation

Bootstrap problem: a new sovereign with no existing peers needs some starting point for discovery. Seed nodes provide that starting point.

**Nature of seed nodes:**
Seed nodes are substrate installations run by trusted operators (foundation, community organizations, established sovereigns) whose role is to introduce new sovereigns to the mesh. They maintain directory-of-directories, host commons reputation registries, respond to bootstrap queries with peer suggestions.

**Federation discipline:**
No single seed node has authoritative discovery. Multiple independent seed operators, geographic and jurisdictional diversity, federation working spec for cross-seed communication. New sovereigns query multiple seeds; consistency across seeds informs trust.

**Governance:**
- Seed operators publish operating charter (what they include in bootstrap, what they exclude, reputation criteria)
- Commons reputation signals track seed-operator behavior over time
- Operators can rotate their seed preferences via ceremony
- Foundation-run seeds are one entry in the federation, not authoritative

**Trust properties:**
- Solves the "first peer" bootstrap problem
- Reputation-weighted per DISTRIBUTED-KNOWLEDGE-COMMONS — some seeds trusted more than others based on community consensus
- Federated — no single point of compromise; multiple seeds cross-verify

**Attacks:**
- Seed operator compromise: mitigated by federation and cross-seed verification; single compromised seed cannot dominate discovery
- DDoS on seed nodes: geographic and administrative distribution across multiple operators
- Bootstrap-time injection: attacker races to introduce fake peers to new sovereigns; mitigated by multi-seed cross-check and vouching layer

### Layer 3 — Vouching receipts

Peer-vouching enables organic mesh growth. Trusted peer A introduces peer B to peer C by emitting a vouching receipt.

**Vouching receipt structure:**

```
peer:vouching:issued
  fields:
    voucher: <voucher_genesis_pubkey>
    vouched_for: <vouched_genesis_pubkey>
    vouched_for_directory_ref: <optional URI to vouched-for's directory listing>
    scope: <what the voucher attests>
      - "know_them": voucher knows the vouched-for personally
      - "worked_with": voucher has done substrate operations with them
      - "kindred_with": voucher has kinship with them (may be scope-limited)
      - "professionally_referred": voucher is professionally referring them
    context: <optional freeform justification, operator-declared>
    expiry: <optional timestamp>
    signature: <voucher's Genesis signature over content>
    timestamp: <iso8601>
```

Vouching receipts are chain-anchored on voucher's chain and can be distributed to inquirers via any channel. Inquirer's substrate verifies signature against voucher's Genesis, verifies voucher is trusted by inquirer (via peer-trust-anchor or via reputation), and treats the vouching as informational input to the operator's judgment about the vouched-for.

**Lifecycle:**
- Issue: voucher signs receipt with scope declaration
- Distribute: receipt accompanies vouched-for's introduction to third parties
- Verify: inquirer's substrate verifies signature and voucher's own trust
- Consider: inquirer's operator judges whether to accept vouching as trust input
- Revoke: voucher can emit `peer:vouching:revoked` receipt at any time; revocation propagates via chain distribution

**Trust properties:**
- Web of trust — organic mesh growth via vouching chains
- Signature-verifiable — Genesis-signed prevents fabrication
- Scope-declared — voucher's scope of knowledge is explicit
- Revocable — voucher can withdraw vouching if relationship deteriorates
- Chain-anchored on voucher's chain — provides accountability

**Attacks:**
- Vouching sybil attacks: attacker creates many vouching-authorized identities to bootstrap fake peer trust; mitigated by voucher-reputation and network-topology analysis
- Coerced vouching: attacker compels voucher to issue false vouches; hard to detect substrate-side but chain-visible revocation supports recovery
- Vouching chain manipulation: long chains of vouching (A vouches for B, B vouches for C, ...) don't automatically transfer trust; each step requires operator judgment

### Layer 4 — Rendezvous signals

One-shot, time-bounded, intent-declared discoverability. Novel primitive worth naming distinctly.

**Use case:** operator attends a conference, community gathering, professional event. Wants to be discoverable for the duration of the event to attendees who possess a shared context token. Not always-on; not published in public directory; not requiring vouching.

**Rendezvous signal structure:**

```
rendezvous:signal:published
  fields:
    signaler: <operator_genesis_pubkey>
    context_token: <shared_secret_hash>  // pre-shared with intended audience
    scope: <how discoverable>
      - "physical_proximity": short-range beacon carrying this signal
      - "commons_channel": commons-hosted rendezvous board for a time-bounded event
      - "direct_query": inquirers query for signals matching context_token
    validity_window: <start_time>, <end_time>
    contact_hint: <how to establish next-step contact if match>
    signature: <signaler's Genesis signature>
```

**Signal lifecycle:**
- Emission: operator publishes signal at event start
- Discovery: intended audience queries for signals matching context_token
- Contact: discoverer establishes initial contact via hint (introduction on-chain, direct message via provided channel)
- Expiry: signal auto-expires at validity_window end
- No persistence beyond expiry: rendezvous is inherently ephemeral

**Trust properties:**
- Time-bounded discoverability
- Context-token gated — only pre-shared audience discovers
- Signature-verifiable — Genesis-signed signals prevent impersonation
- Ephemeral by construction — doesn't accumulate persistent surface

**Attacks:**
- Context token leaked to attackers: rendezvous is discoverable by unintended audience; mitigation via short window, small context tokens, per-event token distribution
- Signal replay: window enforcement prevents replay outside validity window
- Adversarial rendezvous flooding: rate limits, event-organizer-authorized rendezvous boards for large events

Rendezvous signals extend COPRESENCE-BEACON-PROTOCOL as a new beacon type (Type 6) when transmitted over short-range physical channels; they also exist as commons-hosted board entries when transmitted over internet channels.

### Layer 5 — Private-mode direct address exchange

For sovereigns who have no public directory listing and share no rendezvous context, discovery happens through direct address exchange over any secure channel (in-person, encrypted messaging, phone call, physical letter).

**Content of address exchange:**
- Sovereign's Genesis public key or fingerprint
- Optional contact channel for initial substrate communication
- Optional vouching from mutual peer, delivered alongside

**Trust properties:**
- Manual: doesn't scale to arbitrary peer counts
- Sovereign-controlled: operator chooses what to share and with whom
- Signature-verifiable: subsequent substrate operations verify against exchanged Genesis public key

**Attacks:**
- Attacker intercepts address exchange: uses channel's own security properties (encrypted messaging, in-person, etc.)
- Attacker impersonates in initial substrate contact: post-exchange operations verify against exchanged Genesis; impersonation without Genesis compromise fails
- Man-in-the-middle at exchange: mitigated by verification via second channel (voice call to confirm public key fingerprint, etc.)

This is the layer for household-forming sovereigns, close family, professional relationships that predate substrate adoption, and any relationship where the operator wants to be found through personal introduction rather than infrastructure discovery.

## The onboarding ceremony chain

New sovereign to first kinship — the full progression across discovery + trust anchor + kinship:

### Phase 1 — Discovery

New sovereign uses one of the five layers to find candidate peers:
- Query seed nodes (Layer 2) for initial suggestions
- Look up specific sovereigns via public directory (Layer 1)
- Receive vouching receipts from mutual peers (Layer 3)
- Match on rendezvous signals at events (Layer 4)
- Receive direct address exchange from personal contact (Layer 5)

Chain-anchored: `peer:discovered:<peer_id>:<discovery_layer>:<discovery_id>` receipt records each discovery event.

### Phase 2 — Verification

New sovereign's substrate verifies discovered peer:
- Signature verification against discovered peer's Genesis
- Substrate integrity attestation check (per SOFTWARE-INTEGRITY-ATTESTATION)
- Commons reputation lookup for peer
- Cross-verification via multiple discovery layers if available

Chain-anchored: `peer:verification_complete:<peer_id>` receipt.

### Phase 3 — Peer trust anchor grant

Operator ceremony per PEER-TRUST-ANCHOR-2026-07.md — grants specific admission surfaces (chain admission, extension admission, observation reference, commitment endorsement, delegation federation, reputation input). Fine-grained per surface; not universal trust.

Chain-anchored: `peer:trust_anchor:granted:*` receipts per surface granted.

### Phase 4 — Ongoing observation

Substrate observes peer behavior across granted surfaces. Officer cadre monitors for anomalies. Cognitive Self-Observer verifies peer-related claims against ground truth. Reputation signals flow through commons.

### Phase 5 — Kinship declaration (optional)

If operator wishes deeper relational context per SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md, kinship declaration ceremony. Not required for peer operations; specifically declared when the relationship's depth warrants.

Chain-anchored: `kinship:declared:*` receipts.

Each phase produces chain-visible evidence. Any operator can walk any peer relationship back through the discovery layer, verification steps, trust anchor grants, and (if applicable) kinship declarations.

## Composition with existing specs

- **PEER-TRUST-ANCHOR-2026-07.md**: discovery precedes trust-anchor grants. Discovery layer produces candidate peers; PEER-TRUST-ANCHOR governs admission-surface authorization. No changes to peer-trust-anchor; discovery is the layer above.
- **SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md**: kinship follows peer-trust-anchor. Discovery is the outermost layer; kinship is the innermost.
- **COPRESENCE-BEACON-PROTOCOL-2026-07.md**: rendezvous signals extend beacon types (new Type 6). Private-mode short-range discoverability composes with existing beacon envelope.
- **DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md**: reputation signals for directory listings, vouching claims, seed nodes, and rendezvous boards all flow through commons.
- **SHARED-SPACE-SENSING-ETIQUETTE-2026-07.md**: private-mode discoverability defaults are analogous to bystander preference defaults — operator controls their discoverability.
- **SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md**: directory listings include substrate integrity attestations; inquirers verify the sovereign at the other end is running a legitimate substrate.
- **PEER-DISCOVERY-AS-OUTREACH-2026-07.md**: this spec supersedes and elaborates the earlier peer-discovery framework. Rendezvous signals and vouching receipts are new; public-directory and seed-node layers formalize what was previously implicit.
- **COMMUNITY-SURFACE-ARCHITECTURE-2026-07.md**: community gathering surfaces can be a channel for rendezvous signal distribution and vouching introductions.

## Attack model

- **Attacker impersonates via forged directory listing**: signatures verify against operator's Genesis; forgery requires Genesis compromise. Signed listings prevent this class.
- **Attacker floods with sybil identities in public directories**: reputation flow via commons, low default trust for new listings, network topology analysis catches sybil patterns over time.
- **Attacker compromises seed node**: federated architecture provides resilience — single compromised seed cannot dominate. Cross-seed verification detects inconsistency. Commons reputation on seed operators tracks trust over time.
- **Attacker DDoSes seed nodes**: geographic and jurisdictional federation distribution; multiple independent seed operators prevent single-source failure.
- **Attacker abuses vouching to introduce malicious peers**: voucher-reputation is at stake; voucher who introduces bad actors gets reputation-flagged in commons; voucher's own trust anchor grants may be revoked by inquirers.
- **Attacker leaks rendezvous context token**: short window and small context tokens limit exposure; specific-event tokens don't reuse across events.
- **Attacker manipulates address-exchange channel**: channel-specific security properties (encrypted messaging, in-person exchange, voice verification of key fingerprints) provide defense.
- **Attacker sybil-vouches (creates many identities to vouch for each other)**: mesh-topology reputation analysis, voucher-diversity requirements, commons reputation weighting catch this pattern.
- **Attacker exploits bootstrap-time freshness**: new sovereign has no reputation history; may accept low-quality first peers. Substrate surfaces "no reputation history yet" prominently in operator UX to inform judgment.

## Failure modes

- **Discovery yields zero candidates for new sovereign**: no seeds accessible, no directory listings found for known peers. Operator has to bootstrap via Layer 5 (personal introduction) alone.
- **Vouching receipts too old to be relevant**: vouching from a peer who's since become distant. Voucher-freshness weighting via time-decay.
- **Rendezvous signal window mismatch**: signal expired before recipient discovers it. Retry with fresh signal.
- **Public directory listing corrupted or removed**: peer becomes undiscoverable via that layer. Fallback to other layers (vouching, previous contact history) or direct address exchange.
- **Commons reputation manipulated**: reputation signals biased. Mitigated by cross-commons verification, operator judgment as ultimate arbiter.
- **Seed federation splits (multiple non-communicating seed clusters)**: mesh fragments into subgraphs. Sovereigns discovered via one cluster don't appear via another. Bridge sovereigns (present in multiple clusters) heal fragmentation over time.
- **Attacker exploits fresh-sovereign posture to gain trust anchor**: substrate surfaces "peer has no reputation history" to operator; operator judgment about accepting trust anchor with unknown peer.

## Non-goals

- **Not universal identity registry**. No canonical directory of all sovereigns. Discovery is layered and federated.
- **Not automatic trust**. Discovery produces candidate peers; trust anchor grants require operator ceremony.
- **Not surveillance surface**. Public listings are voluntary; private-mode discovery is deliberate.
- **Not routing infrastructure**. Substrate uses existing internet routing; doesn't build overlay networks.
- **Not sybil-proof by construction**. Sybil resistance is reputation-and-topology-based; deep sybil resistance requires substrate maturity and commons participation.
- **Not automated peer suggestion**. Substrate does not autonomously recommend peers based on activity patterns; suggestion is operator-initiated queries against seed nodes and directories.
- **Not censorship-resistant at the routing layer**. Using the current internet inherits its routing-layer censorship surfaces. Rendezvous signals over short-range physical channels provide some resilience; deep resistance requires additional infrastructure.

## Open positions

- **Seed federation governance schema**. What's the charter format for seed operators? How is federation membership managed? Rotation, admission, revocation of seed status.
- **Well-known URI format canonicalization**. `/.well-known/zeropoint/sovereign.json` — federation working spec for exact JSON schema and required fields.
- **DNS TXT record schema for `_zp` prefix**. Federation working spec.
- **Rendezvous board hosting protocol**. Commons-hosted rendezvous boards for events. Discovery, integrity, expiry mechanics.
- **Voucher-reputation weighting algorithm**. How do commons reputation signals compose across voucher relationships? Network-analysis approaches.
- **Multi-seed cross-verification protocol**. How do multiple seed queries compose into a consensus discovery result? Consistency thresholds.
- **Onboarding UX for fresh sovereigns**. First-time operator UX for the five-layer discovery. Which layers introduced when? How does operator judge trust in new peer with no history?
- **Substrate-integrity attestation freshness**. Directory listings include attestation; how often must attestations be re-generated? Composes with REPRODUCIBILITY-CEREMONY.
- **Commons-directory publication protocol**. Community-run directories for regional or thematic sovereigns. Federation working spec for cross-directory reputation flow.
- **Discovery-layer choice UX**. Operator UX for choosing which discovery layer to use per peer relationship. Automation vs explicit selection.

## What composes from here

Immediate design work:

1. **Public directory listing JSON schema** — canonical format for `/.well-known/zeropoint/sovereign.json`
2. **DNS TXT record format** — `_zp.<domain>.` schema
3. **Vouching receipt schema** — chain-anchored voucher structure
4. **Rendezvous signal schema** — extending COPRESENCE-BEACON-PROTOCOL with Type 6
5. **Seed node protocol** — bootstrap query and response format
6. **Discovery event chain-anchoring** — receipts per discovery layer

Near-term implementation:

1. **Discovery runtime** in `crates/zp-server/src/discovery/`
2. **Layer-specific discovery adapters** (directory, seed-federation, vouching-verification, rendezvous, direct-exchange)
3. **Chain-anchored discovery event emitters**
4. **Substrate integrity attestation integration** with directory listings
5. **Commons reputation integration** with discovery results
6. **Dashboard discovery panel**: recent discoveries, active vouchings held, pending rendezvous, seed connections
7. **CLI verbs**: `zp discovery seed query`, `zp discovery voucher issue|list|revoke`, `zp discovery rendezvous publish|match`, `zp discovery listing publish|update`

## Framing note

Discovery and Bootstrap addresses how sovereigns find each other in a mesh built on top of the existing internet. Same principle as chain-anchored discipline elsewhere — operator authority chain-anchored per discovery event, trust properties preserved at each layer, ceremony-visible progression from discovery through peer trust anchor to kinship.

The load-bearing insight: **discovery is layered, not monolithic.** Five distinct discovery layers serve different use cases, carry different trust properties, and compose through operator judgment. Public directory for professional discoverability; seed nodes for bootstrap; vouching for organic mesh growth; rendezvous for time-bounded event discoverability; direct exchange for personal relationships. No single layer solves the whole problem; together they cover the range of ways sovereigns actually find each other.

Combined with the substrate's structural discipline across every trust boundary, discovery and bootstrap completes the outermost layer of the trust envelope. What was previously implicit — "somehow you find your peers, then you trust them, then you deepen the relationship" — becomes structural: discovery layer chosen per interaction, verification chain-anchored, peer trust anchor operator-ceremonied, kinship declared when relational depth warrants. Sovereignty is preserved because operator judges every discovery event and dispositions every progression step. Safety is preserved because signatures verify at every layer and reputation flows through commons. Continuity is preserved because chain records the full trust-genesis of every peer relationship — from first discovery through current state — enabling operators to reason about their mesh with full historical context. The substrate uses the current internet as its discovery substrate; the trust chain does the sovereignty work.
