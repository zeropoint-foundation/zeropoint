# Peer Discovery as Outreach — July 2026

**Document type:** Architectural note. Establishes the canonical answer to "how does the Foundation, or any party, reach ZeroPoint operators after installation, in a system that has no center by design?" Sits under `ARCHITECTURE-2026-07.md` Part II §4 (trust-as-grammar) and Part I §1.1 (there is no center). Grounds §11 of `PERSONALITY-ADAPTATION-VALIDATION-PROTOCOL-2026-07.md` where recruitment mechanics are otherwise left open.

**Status:** Design note. The primitives it depends on already exist in `zp-mesh` and the Presence Plane; what needs to be built is enumerated in Part VII.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-05.

---

## Part I — The Problem That Has No Conventional Answer

### 1. The centralization instinct

Every established pattern for reaching users after installation assumes a center. Email lists, push notification tokens, analytics endpoints, telemetry beacons, mailing-list sign-ups — all of them work by accumulating a directory of installed nodes at a central party, then pushing from that directory when the party wants to reach its users. The center holds a list. The list is queryable, breachable, subpoenable, and — over long enough time — always monetized.

ZeroPoint is designed to make that architecture impossible. There is no server the Foundation runs that receives phone-home traffic on install. There is no user account created when a Genesis ceremony completes. There is no central directory of "operators running ZP" anywhere. The Presence Plane's structural amnesia (whitepaper §7) is not a policy — it is an architectural inability to accumulate the list that every conventional outreach mechanism would require. Working as intended, and now costing us the frictionless outreach the same architecture was built to prevent.

### 2. Why the obvious workarounds fail

Two workarounds present themselves and both fail on the same principle.

**Email registration.** Capture emails at install or via a public form. The Foundation now has a mailing list. This solves the outreach problem completely and undoes the sovereignty property completely. The Foundation would hold a centralized identifier for each operator that has all the pathologies chain-anchored identity was designed to eliminate: it's subpoenable, breachable, recoverable via password reset (undermining the strong-key property of Genesis identity), and it creates a bridge from real-world identity to pseudonymous chain identity that a determined adversary can walk. Worse, the plumbing outlives the intent: today's "we'll only use this for research invitations" becomes tomorrow's segmented marketing list, not through malice but through the ordinary organizational drift that happens whenever the plumbing exists.

**Foundation-hosted chain feed.** Foundation publishes announcements to a known chain, operators poll it. Half-right — the announcements are chain-anchored, signed, verifiable, revocable-via-mandate — but still centralized at the level of the location. The Foundation is still the singular publisher; the singular publisher location becomes an attack surface (censor the location, censor the outreach); and the model implicitly assumes the Foundation as a privileged coordinator. Better than email, but still a center.

### 3. The right frame

Outreach is peer discovery.

The mechanism by which anyone — the Foundation, another operator, a fleet, a peer-to-peer service — reaches a ZeroPoint operator is the same mechanism by which peers find each other on the mesh. Announce packets propagate. Subscribed nodes filter locally. Nobody accumulates a list. The Foundation is a peer with a distinguished destination hash, not a directory holding a subscriber database.

The conventional outreach problem dissolves because it was the wrong problem. The right problem is: *what does peer discovery, generalized to include broadcast messaging, look like when engineered for a sovereign substrate?*

---

## Part II — The Principle

### 4. Peer discovery IS the outreach primitive

There is no separate "outreach subsystem" in ZeroPoint. Outreach is a use case of the peer-discovery substrate that already exists. Every party that wants to reach operators becomes a peer that broadcasts; every operator that wants to receive broadcasts subscribes to categories from specific sources at the local filter level. The mesh delivers the announces; the operator's substrate applies the filter.

### 5. The Foundation is a peer, not a directory

The Foundation participates in this substrate as one peer among many. It has a Genesis-derived key (the Foundation's own Genesis, distinct from any operator's) and a destination hash derivable from that key. It emits announces addressed to its own destination, signed by its own key. Operators who have chosen to subscribe to Foundation-category announces receive them via ordinary announce propagation. Operators who have not, don't.

The Foundation holds no list of subscribers. It publishes; whoever is listening hears. The only operators the Foundation ever knows about individually are those who have explicitly issued capability-grant mandates to it — a much smaller, opt-in, revocable set. The default state is that the Foundation and any given operator have no relationship the Foundation is aware of.

### 6. Broadcast plus local filter, not database plus push

The paradigm shift, stated plainly:

| Conventional model | ZP model |
|---|---|
| Central database of subscribers | No database |
| Publisher pushes to specific known recipients | Publisher broadcasts to whoever is listening |
| Subscribe = give the publisher your identifier | Subscribe = configure a local filter |
| Unsubscribe = the publisher removes you | Unsubscribe = you stop filtering the source in |
| Publisher knows who its subscribers are | Publisher never knows who is listening |
| Compromising the publisher exposes the list | There is no list to expose |

Every property in the right column is preserved by construction because the primitive doing the work is peer discovery, not a subscriber database.

---

## Part III — Reticulum as Precedent

### 7. What Reticulum gets right

Reticulum's networking model — which ZP already interoperates with at the wire level in the Presence Plane's mesh backend — solved this problem for physical-mesh networking:

- **Announces are signed identity broadcasts.** Each announce packet carries the announcing node's public key, a destination hash, and any capability metadata, all signed by the node's key. Under 400 bytes; single-packet on LoRa.
- **Destination hashes uniquely identify endpoints without hostnames or IPs.** 128-bit truncated SHA-256 of a public key. No DNS, no CA, no lookup service.
- **Announces propagate via any transport.** LoRa, WiFi, serial, TCP — the announce format is transport-agnostic; a node with multiple interfaces bridges them.
- **Path discovery is passive.** Nodes learn how to reach destinations by observing announces propagate through them. No routing protocol required.
- **No hierarchy.** Every node is a full peer. There are no directory servers, no root nodes, no privileged coordinators.

### 8. What ZP inherits

The Presence Plane's Reticulum-compatible mesh backend already carries all of the above. The announce wire format ZP uses (`[combined_key(64)] + [capabilities_json] + [ed25519_signature(64)]`) is a Reticulum-shaped announce with capability metadata suitable for governance-layer filtering. Path discovery works. Destination hashing works. Transport-agnosticism works.

What ZP inherits, then, is a working substrate for the "broadcast + local filter" model. What needs to be added is the semantic layer that turns raw announces into a formal outreach primitive with category vocabulary, signed authority, and cockpit-level subscription controls.

### 9. What ZP extends beyond Reticulum

Reticulum's announces are primarily about network reachability. ZP's announces carry additional weight:

- **Semantic categorization.** A namespaced category vocabulary that operators subscribe to selectively (research invitations, security advisories, protocol updates, peer greetings, service offers).
- **Governance-layer authentication.** Announces are signed by Genesis-derived keys, so a signed announce carries the same chain-of-identity that any other governed action carries. An operator can verify not just "some key signed this" but "this key traces to a Genesis with the following historical governance posture."
- **Reputation weighting.** Announce propagation is not neutral — peers whose historical announces have been ignored propagate at reduced weight; peers with sustained positive reputation propagate more broadly. The reputation system already exists in `zp-mesh`; the announce path composes with it.
- **Capability metadata.** Announces can carry a hash reference to a capability mandate template that receivers can inspect and, if they choose to engage, issue against.

---

## Part IV — Mechanism

### 10. Announce structure

An outreach announce has three semantic layers on top of the base Reticulum-compatible wire format:

- **Source** — Ed25519 public key of the emitting peer, and its destination hash. Signed by the private key. This is the announce's cryptographic identity.
- **Category** — namespaced string identifying the announce type. See §11.
- **Payload** — small (bounded ≤ a few hundred bytes to fit single-packet propagation): human-readable summary, optional receipt hash pointing to full detail chain-anchored elsewhere, optional capability-mandate template hash the announce is soliciting.

The signature covers all three layers. Any recipient can verify locally that the announce is well-formed and authentically from the claimed source.

### 11. Category taxonomy

Categories are namespaced by emitter. The Foundation reserves and publishes its own namespace; other parties reserve theirs. Reserved namespaces are announced (recursively — the Foundation emits an announce reserving `foundation:*` shortly after its Genesis) so any peer can verify claimed namespace ownership against chain-anchored reservations.

Initial Foundation namespace:

- `foundation:research:invitation` — invitations to participate in a research study; carries capability-mandate template hash for the study.
- `foundation:security:advisory` — security notices affecting deployed substrate versions.
- `foundation:protocol:update` — changes to protocol behavior operators should be aware of.
- `foundation:capability:announcement` — new capabilities or affordances shipping in a release.
- `foundation:governance:notice` — governance events (constitutional interpretations, foundation posture changes) operators should know about.

Operator-side namespaces are unreserved and can be minted freely. An operator running a specialized fleet might emit `myfleet:onboarding:request` announces to solicit new fleet members. Two peers meeting on the mesh might use `peer:greeting:hello` as a discovery handshake.

### 12. Local subscription filters

Each operator's substrate holds a subscription filter — a local file, controlled by the operator, of the shape "for source S, accept categories C1, C2, ..." Announces are evaluated against the filter as they arrive:

- Signature verification (always).
- Source authentication (does the source's Genesis chain match what the operator has previously accepted as the source's identity?).
- Category match against the filter (does the operator subscribe to this category from this source?).
- Reputation floor (is the source above the operator's minimum reputation threshold?).

Announces that pass all four are surfaced to the operator through the Regent, which decides how to present them (see §14). Announces that fail are dropped without emitting anything back to the source. The source never learns that a given operator dropped its announce.

### 13. Mandate lifecycle for opt-in engagements

An announce that solicits engagement — a research invitation, a service offer, a fleet-joining opportunity — carries a hash reference to a capability-mandate template. If the operator wishes to engage, the flow is:

1. Operator dereferences the mandate template from the referenced hash (delivered via mesh or fetched from a known chain reference).
2. Operator's substrate presents the mandate terms: what capability is being granted, to whom, for what purpose, with what scope, for what duration, revocable.
3. Operator reviews. Regent may explain, may highlight terms that look unusual, may recommend approval or refusal based on posture context (per Part IV of the whitepaper).
4. If operator accepts, they issue a signed mandate to the requesting party. The mandate is a normal chain-anchored delegation — same primitive as any other capability grant.
5. From that point, the requesting party has authority within the mandate's scope. Any action within scope is receipted on both sides. Revocation is a single receipt from the operator.

The Foundation's role in the study invitation flow is: emit the research-invitation announce, receive mandates from consenting operators, run pre-registered queries authorized by those mandates, respect revocation.

### 14. Cockpit presentation

Announces that pass the filter reach the Regent, which surfaces them through the presentation layer per operator preference:

- **Minimal fidelity.** Text summary appended to a `zp announces` list; operator can browse and evaluate at their own pace.
- **Standard fidelity.** Regent may proactively surface announces categorized as high-priority (security advisories, for example) into the conversational surface; lower-priority announces (research invitations) accumulate in a queue.
- **Secure fidelity.** Announces are rendered server-side; the surface behaves identically but the client only sees pixels.

The presentation layer never auto-accepts anything. Every engagement (issuing a mandate, following an embedded link, revealing operator identity to a source) requires an explicit operator signature. Announces are proposals; the operator signs.

---

## Part V — Design Decisions

### 15. Foundation destination discovery (the one bootstrap concession)

The peer-discovery model requires that a fresh install know at least one starting destination to subscribe to Foundation announces. This is a bootstrap problem — the same one Bitcoin solves with hardcoded seed nodes and Reticulum solves with default configured transport announces.

The concession is minimal and structurally auditable:

- The Foundation's Genesis-derived public key and destination hash are baked into the release package as a `foundation-identity.toml` file.
- The file is signed by the release-signing key, which itself is signed by the Foundation's Genesis key. Verification is a two-step: verify the release signature, verify the Foundation Genesis lineage.
- Operators can independently verify the Foundation identity against multiple sources: the release signature, the source repository, mesh peer confirmations from operators the fresh install trusts.
- The Foundation identity is not a trust root for governance — it is only a subscription hint. An operator can subscribe to Foundation announces by verifying this identity, but nothing about the substrate's governance depends on the Foundation.

### 16. Key rotation via transition announces

If the Foundation's key must be rotated (compromise, hardware turnover, key-hierarchy migration), the transition is announced through the mesh under a reserved category `foundation:identity:transition`. The transition announce is signed by *both* the old key and the new key, and includes a chain reference on the Foundation's own chain proving the transition ceremony was performed correctly.

Operators receiving the transition announce verify:

- Both signatures verify against their respective keys.
- The old key's chain shows the transition ceremony as a valid receipt.
- The new key's Genesis-derived lineage is consistent with the ceremony's terms.

If all three verify, the operator's substrate updates its local subscription filter to route Foundation-category announces to the new destination. This is a chain-anchored governance event; it is not a magic override.

Fresh installs shipping between the transition and the next release update the old key naturally through the transition announce discovered via mesh.

### 17. Spam resistance

Any peer can broadcast. What stops the mesh from being flooded with garbage?

Three composed mechanisms, none sufficient alone:

- **Reputation-weighted propagation.** Announces from sources with historically-ignored broadcasts propagate at reduced weight — peers with poor propagation reputation are hop-limited more aggressively. This is a system-wide equilibrium; specific announces are not censored, but a source that consistently produces ignored traffic finds its future traffic reaches fewer peers.
- **Local subscription filters.** Even a broadcasted announce reaches only operators whose filters accept the source and category. An unsolicited broadcast from a peer the operator has not subscribed to is dropped at the operator's substrate before reaching any surface.
- **Cost to broadcast.** Announce emission requires computational work proportional to intended reach (a proof-of-work component, calibrated to make high-fanout broadcasts non-trivial). Small-scale peer-to-peer announces are effectively free; global-scale flooding costs meaningfully.

None of these are perfect. Together they make cost-effective spam infeasible without eliminating benign broadcasting.

### 18. Subscription state is local

An operator's subscription state — which sources they accept, which categories they filter, which reputation thresholds they apply, which announces they have received and archived — lives on the operator's own chain and in local configuration. No third party holds any part of the operator's subscription state.

This means:

- The Foundation never knows who is subscribed to its announces.
- Subscription changes require no notification to any source.
- Subscription state is queryable only by the operator (or by anyone the operator has delegated a chain query mandate to, at the operator's discretion).
- A breach of the Foundation exposes announce emissions but not subscription records — because there are no subscription records at the Foundation.

### 19. Muting and blocklists

An operator can add any source to a local blocklist. Blocked sources' announces are dropped without evaluation. The block is local; the blocked source is not notified. This composes with subscription filters — the blocklist is checked first, before category filtering, so an operator can block a source globally without needing to unsubscribe from each category individually.

Blocklists never leave the operator's substrate. There is no shared reputation blocklist across operators (which would create a coordination point that the architecture avoids). Reputation degradation happens through the reputation-weighted propagation mechanism (§17), which is emergent from peer behavior rather than centrally maintained.

---

## Part VI — The General Pattern

### 20. Beyond the Foundation's use case

The pattern this document describes is not specific to the Foundation-to-operator direction. It generalizes:

**Operator-to-operator discovery.** Two operators wanting to find each other emit `peer:greeting:hello` announces. If both have subscribed to peer-greeting announces from unknown sources (or from each other's known Genesis), they discover each other and can initiate an introduction ceremony.

**Fleet-to-fleet coordination.** A fleet emitting `myfleet:coordination:offer` announces can find peer fleets for cross-fleet governance protocols. The mandate framework composes: fleet A grants fleet B a scoped mandate for the coordination purpose, receipted on both fleets' chains.

**Service offers.** Any operator with a chain-attested capability to offer (skill, tool, cognitive service) can emit announces soliciting engagement. Interested operators dereference the mandate template, evaluate, engage.

**Distress signals.** An operator whose substrate has detected an integrity concern or an ongoing attack can emit `peer:security:distress` announces, alerting subscribed peers. This is peer-to-peer defense infrastructure, not centralized alerting.

**Research recruitment beyond the Foundation.** Any party — academic institution, independent researcher, another Foundation — can conduct ZP-substrate studies using the same announce-and-mandate pattern. The Foundation has no privileged role in research; it uses the same primitive anyone else can use.

### 21. What the pattern replaces

Every conventional pattern the pattern replaces has a centralized-directory shape that the substrate cannot host:

| Conventional | Peer-discovery equivalent |
|---|---|
| Mailing list | Category subscription + announce broadcast |
| Push notifications | Announce with high-priority category classification |
| Analytics beacons | Chain-anchored capability-grant mandates for research queries |
| App store | Category-tagged capability announcements + operator-side installation decisions |
| Directory service | Emergent peer discovery via announce propagation |
| Central alerting | Peer-to-peer distress announces |

Not every one of these replacements ships in the first version. But the pattern generalizes to all of them, so each one becomes an incremental application of an existing primitive rather than a novel centralized service.

### 22. What the pattern does not replace

The pattern is not a universal substitute for all inter-party communication. It does not do:

- **Real-time low-latency messaging.** Announce propagation is best-effort mesh delivery, not sub-second messaging. For real-time exchanges, peers who have discovered each other can establish direct links using the same mesh primitives.
- **Bulk data transfer.** Announces carry small payloads (single-packet on LoRa). Bulk data transfer between peers is a separate mechanism, initiated via a mandate-scoped session established after peer discovery.
- **Highly private one-to-one communication.** Announces are broadcasts; anyone listening at the wire level can see them (though only cryptographically-authorized recipients can decrypt payload contents, if the announce carries encrypted content). For private communication, established peers use encrypted direct links, again scoped by mandate.

---

## Part VII — What Needs to Be Built

The primitives already ship. The following are additions that turn the primitives into the outreach pattern this document describes:

- **Announce category taxonomy definition.** The `foundation:*` namespace with initial categories; the operator-namespace registration mechanism; the recursive-announce pattern for namespace reservation.
- **Local subscription filter format and cockpit surface.** A TOML-schema for `~/ZeroPoint/subscriptions.toml`; a CLI (`zp subscribe`, `zp unsubscribe`, `zp announces`, `zp block`) for managing it; a Regent-side surface for reviewing incoming announces.
- **Foundation identity bootstrap file.** `foundation-identity.toml` in the release package; the two-step release-signature-plus-Genesis-lineage verification implementation in `zp-keys`.
- **Key rotation transition-announce protocol.** The dual-signed transition announce format; the operator-side verification and filter-update flow.
- **Proof-of-work component for high-fanout broadcasts.** Calibrated cost function; announce-emission gate in `zp-mesh`.
- **Reputation-weighted propagation.** Integration between the existing reputation system in `zp-mesh` and the announce propagation logic — specifically, the hop-count adjustment based on source reputation.
- **Mandate template dereferencing.** Given a mandate template hash carried in an announce, retrieve the template (via mesh or chain reference), present it to the operator via the Regent, produce the signed mandate on acceptance.

None of these are large. Each fits within a discrete `zp-*` crate. The design pattern is coherent because the primitives underneath already are.

---

## Part VIII — Immediate Application: The Personality-Adaptation Study

The personality-adaptation validation protocol (`docs/PERSONALITY-ADAPTATION-VALIDATION-PROTOCOL-2026-07.md`) has a recruitment problem: how does the Foundation reach potential participants without violating the sovereignty properties the protocol depends on?

Under this document's pattern, recruitment works as follows:

1. The Foundation emits an announce under `foundation:research:invitation` with payload: brief study description, capability-mandate template hash for the study, and pointers to the full protocol chain address.
2. Operators whose subscription filters accept `foundation:research:invitation` announces receive it. The Regent surfaces it (per §14) as an actionable invitation.
3. Interested operators dereference the mandate template, review the study terms (arm assignment, per-participant query authority, revocable window, aggregation scope), and — if they consent — issue the mandate to the Foundation.
4. The Foundation runs pre-registered queries authorized by the mandate. Every query is receipted (per Part III §12 of the protocol). Analysis is re-derivable.
5. Any participant can revoke the mandate at any time. Revocation is a single receipt. The Foundation's future queries fail.

The Foundation never has a subscriber list, never has an email database, and never gains identifying information about anyone except the operators who explicitly issue mandates. The set of operators the Foundation ends up knowing about is exactly the set that has opted in, and no larger. This is the sovereign-aligned participation model the protocol assumed but did not previously specify.

---

## Part IX — Companion Documents

- `docs/ARCHITECTURE-2026-07.md` — canonical architecture record; this document elaborates the "there is no center" property in Part I §1 with a concrete outreach mechanism.
- `docs/whitepaper-v9.md` — public thesis; §7 (Mesh Transport and the Presence Plane) describes the primitives this document builds on.
- `docs/PERSONALITY-ADAPTATION-VALIDATION-PROTOCOL-2026-07.md` — the study protocol whose recruitment mechanism this document formalizes.
- `docs/design/GOVERNANCE-POSTURE-WIRE-CONTRACT-2026-07.md` — related wire-contract work.

---

*The center does not exist. Outreach happens by broadcast. Subscription happens by local filter. Engagement happens by scoped, revocable mandate. Nobody accumulates a list, because there is nowhere for a list to live. The architecture that made the outreach problem hard is the same architecture that makes the outreach problem soluble — using primitives that were always there, applied to a category of use case that just needed to be named.*
