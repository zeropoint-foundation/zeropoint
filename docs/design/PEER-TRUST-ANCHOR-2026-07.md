# Peer Trust Anchor Management

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` Part VII (Peer-Verification Contract) and §II.15 (substrate boundary planes — specifically the Quarantine Plane's peer-chain admission surface). Specifies how the operator declares which peers are trusted for chain-admission decisions, per-surface scoping of that trust, and revocation mechanics. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `QUARANTINE-PLANE-2026-07.md` (peer chain surface uses trust anchors for admission decisions), `EXTENSION-SURFACE-2026-07.md` (peer-distributed extensions use trust anchors for admission acceleration), `DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md` (reputation composes with trust anchors), `GENESIS-ROTATION-CEREMONY-2026-07.md` (peer rotation notifications update trust anchors).

## Framing

The substrate's trust model is Genesis-derived per KEEL §II.5 — every trust decision anchors on the operator's Genesis. But real substrates operate in mesh with other sovereigns. Chain segments arrive from peers; extensions circulate through peer distribution; observations reference peer identities; commitments span peer relationships. For each of these, the substrate needs to know: does the operator trust this peer, for what, at what depth?

The naive approaches fail predictably. "Trust all peers" is not sovereign — external identities can influence substrate state without operator consent. "Trust no peers" cripples the mesh capability that peer-to-peer messaging is designed for. "Trust based on reputation only" makes reputation manipulation a load-bearing attack surface. Every mainstream federated protocol falls into one of these traps or invents ad-hoc per-protocol trust semantics that don't compose across surfaces.

The Peer Trust Anchor discipline is the substrate's structural response. Operator declares chain-anchored trust anchors: **"I trust peer X for admission surface Y up to trust depth Z."** Every peer-facing surface — chain admission, extension admission, observation reference, commitment endorsement — checks the trust anchor for the specific surface before accepting peer-originated material. Delegation-based, per-surface scoped, chain-anchored, revocable via ceremony. Same discipline the substrate applies internally, extended to peer-facing surfaces.

Three properties frame the discipline:

1. **Chain-anchored trust declaration**. Operator's trust in a peer is a chain receipt (`peer:trust_anchor:granted:<peer_id>:<surface>`), not implicit or configured. Trust changes require ceremony.
2. **Per-surface scoping**. Operator can trust peer X for chain-admission but not for extension-admission; trust X for observation references but not for commitment endorsement. Fine-grained.
3. **Reputation composes as accelerator, never as sole authority**. High reputation peers may auto-admit some artifacts under precedent (per act-on-precedent heuristic); low reputation peers require full operator ceremony. But no reputation level bypasses trust anchor entirely.

## Peer identity

For peer trust anchor to work, peers need stable identities the substrate can reason about.

### Peer Genesis as identity

Each sovereign has a Genesis root per KEEL §II.5. That Genesis's public key is the sovereign's identity in the mesh. Peer trust anchors are declared against peer Genesis public keys.

Peer Genesis rotation (per GENESIS-ROTATION-CEREMONY-2026-07.md) updates the substrate's trust anchor when the rotation notification receipt is received and verified. Operator can accept or reject peer's rotation; accepting means updating the local trust anchor to new Genesis.

### Peer identity persistence

Peer identity survives peer's operational changes (device swaps, form graduations, key rotations). What's constant is the sovereign identity chain from their Genesis. Operator's trust anchor tracks the current authoritative Genesis for that peer.

## Trust surfaces

Trust anchors are declared per-surface. Six canonical surfaces:

### Chain-admission surface

Trust anchor: `peer:trust_anchor:granted:<peer_id>:chain_admission`. Grants: admission of peer-signed chain segments per Peer-Verification Contract (KEEL Part VII).

Depth: full trust (accept all chain segments this peer signs) vs bounded trust (accept only chain segments matching specific action patterns).

Ceremony to grant: operator-signed receipt after review of peer's Genesis chain of custody, peer's reputation in the commons, and any prior operator interactions with that peer.

### Extension-admission surface

Trust anchor: `peer:trust_anchor:granted:<peer_id>:extension_admission`. Grants: expedited quarantine ceremony for extensions signed by this peer.

Depth: auto-admit (operator has pre-consented via ceremony to admit extensions from this peer for specific capability classes) vs review-required (operator still reviews each extension but admission ceremony is faster because trust context is elevated).

### Observation-reference surface

Trust anchor: `peer:trust_anchor:granted:<peer_id>:observation_reference`. Grants: ability for peer's observations to be materialized into local ontology under `HardwareObservation`, `Process`, `Listener`, etc. object types.

Depth: peer's observations can update local ontology directly vs peer's observations are shown as advisory context but require local corroboration.

### Commitment-endorsement surface

Trust anchor: `peer:trust_anchor:granted:<peer_id>:commitment_endorsement`. Grants: peer's commitments (e.g., peer commits to notify us of certain events) are honored by our chain-watcher primitives.

Depth: peer commitments treated as authoritative vs peer commitments treated as informational.

### Delegation-federation surface

Trust anchor: `peer:trust_anchor:granted:<peer_id>:delegation_federation`. Grants: peer can hold delegations from us for specific actions (e.g., peer's Regent can invoke certain of our verbs under scoped delegation).

Depth: fine-grained per delegated verb.

### Reputation-input surface

Trust anchor: `peer:trust_anchor:granted:<peer_id>:reputation_input`. Grants: peer's assessments of other peers (reputation opinions) are counted in our local reputation computation.

Depth: weight applied to peer's opinions (0.0 = ignore; 1.0 = full weight; typically 0.1-0.5 for known peers).

## The trust anchor ceremony

Operator declares a peer trust anchor via chain-anchored ceremony. Four-step flow:

### Step 1 — Peer discovery

Operator becomes aware of peer via one of: mesh discovery, referral from another peer, direct address exchange, community index. Substrate observes peer's identity claims but does not trust yet.

Peer's Genesis public key is captured. Peer's chain of custody (their own chain, if accessible) is optionally reviewed for continuity evidence.

Emit `peer:discovered:<peer_id>` observation receipt.

### Step 2 — Review

Operator reviews peer trustworthiness:
- Peer's Genesis chain integrity
- Peer's activity history on chain
- Peer's community reputation via DISTRIBUTED-KNOWLEDGE-COMMONS
- Prior operator interactions with this peer
- Any warnings from other trusted peers about this peer
- Peer's declared identity claims (do they match observable behavior?)

Optional: Regent-narrated summary of peer's reputation and activity. Regent's summary is advisory only — trust anchor decision is operator ceremony.

### Step 3 — Grant

Operator signs `peer:trust_anchor:granted:<peer_id>:<surface>` receipt with:
- Peer Genesis public key (identity)
- Surface class (which surface this anchor applies to)
- Depth (auto-admit / bounded / advisory)
- Optional expiry (default: no expiry, revoke via ceremony when needed)
- Optional depth-caps (rate limits, scope restrictions)
- Justification (operator's note on why this trust is granted)

Substrate updates its trust anchor set. Peer-facing surfaces observe the anchor and apply appropriate admission depth for peer-originated material.

### Step 4 — Ongoing observation

Substrate continues to observe peer's behavior post-grant. Officer cadre (particularly Cleo and Aegis) narrate patterns and can propose trust-anchor adjustments if peer's behavior shifts.

Cognitive Self-Observer (per COGNITIVE-SELF-OBSERVER-2026-07.md) flags patterns where trusted peer's claims diverge from ground truth.

## Trust anchor lifecycle

**Grant**: as above.

**Adjust**: operator can adjust depth (broaden or narrow) via new ceremony. Example: initially granted `extension_admission` at review-required depth; over time and positive precedent, upgrade to auto-admit for specific capability classes. Emit `peer:trust_anchor:adjusted:<peer_id>:<surface>:<new_depth>`.

**Revoke**: operator revokes via ceremony. Peer's future artifacts at this surface stop admitting. Chain history preserves revocation and previously-admitted artifacts remain admitted (operator can separately re-quarantine if needed). Emit `peer:trust_anchor:revoked:<peer_id>:<surface>`.

**Escalate**: circuit breaker can trigger emergency scope revocation on peer trust anchor per graduated escalation. Reset ceremony requires operator investigation of what caused the escalation.

**Rotate**: when peer rotates their Genesis, their rotation notification receipt arrives. Operator reviews the transition; if accepted, trust anchor updates to new Genesis. Emit `peer:trust_anchor:updated_via_rotation:<peer_id>:<old_genesis>:<new_genesis>`.

## Reputation composition

Reputation is a peer-behavior signal per DISTRIBUTED-KNOWLEDGE-COMMONS. Trust anchor is operator's explicit trust declaration. They compose:

**Reputation accelerates precedent within trust anchor bounds**: a peer with high reputation may have their extensions auto-admitted (per act-on-precedent heuristic) faster than a peer with low reputation — but only within the surface classes for which the operator has granted a trust anchor.

**Reputation does not create trust where anchor is absent**: even a peer with maximum reputation cannot have their artifacts admitted at surfaces where the operator has not granted a trust anchor. Reputation informs; anchor authorizes.

**Reputation loss narrows precedent, not anchor**: if a peer's reputation drops due to negative signals, the precedent-based auto-admit shrinks (their artifacts get more scrutiny again), but the trust anchor itself remains until operator ceremony changes it.

**Reputation is one input among many**: operator ceremony for granting/adjusting/revoking trust anchor considers reputation but is not driven by it. Operator can grant anchor to low-reputation peer (they trust the peer despite reputation) or revoke anchor from high-reputation peer (they distrust despite reputation). Chain-anchored operator judgment is authoritative.

## Peer rotation handling

When peer rotates Genesis (per GENESIS-ROTATION-CEREMONY-2026-07.md), their rotation notification receipt reaches operator's substrate through mesh distribution.

Operator's substrate:
1. Verifies rotation notification receipt is signed by peer's *previously-known* Genesis (or by peer's recovery quorum)
2. Verifies chain integrity of the rotation notification
3. Presents to operator for review — Regent-narrated summary of the rotation context

Operator can:
- **Accept rotation**: update trust anchors from peer's old Genesis to peer's new Genesis. Emit `peer:trust_anchor:updated_via_rotation:*`. All granted surfaces continue at same depth under new Genesis.
- **Reject rotation**: don't update trust anchor. Peer appears with dual identity — trust anchors reference old Genesis which is no longer authoritative; peer's new-Genesis-signed artifacts don't admit. Effectively, operator has broken trust with this peer until investigation resolves.
- **Investigate further**: hold decision. Trust anchors continue to point at old Genesis; peer's new artifacts don't admit; operator gathers more evidence.

Rejection or investigation may indicate the operator suspects peer rotation is compromise-signal (attacker rotated peer's Genesis under attacker control).

## Attack model

Attacker scenarios and how the discipline addresses them:

- **Attacker impersonates a trusted peer**: attacker's signatures don't chain-verify against peer's Genesis. Trust anchor verification catches impersonation.
- **Attacker compromises a trusted peer's Genesis and signs malicious artifacts**: trust anchor is intact but peer's authority is compromised. Operator observes anomalous patterns via Sentinel/Steward/observers on the peer's contributions; can revoke trust anchor. Circuit breaker may escalate on suspected compromise.
- **Attacker manipulates reputation to accelerate trust-anchor grant**: reputation is one input; not the anchor decision itself. Operator can grant despite low reputation or reject despite high; reputation manipulation cannot force operator ceremony outcome.
- **Attacker manipulates peer rotation to gain trust anchor for new (attacker-controlled) key**: rotation notification must be signed by peer's previously-known Genesis (or peer's recovery quorum). Attacker without prior authority cannot forge this. If attacker has prior authority, that's peer Genesis compromise and peer's own substrate should detect and rotate.
- **Attacker collects trust anchors across many operators to build federation authority**: each operator's trust anchor is local. There is no aggregation across sovereigns. Attacker "trusted by 100 operators" is still just an independent trust relationship with each; no compound authority.
- **Attacker gets initial trust anchor by legitimate behavior, then goes rogue**: post-grant observation catches deviations. Cognitive self-observer flags anomalous claim patterns. Officer cadre proposes revocation. Circuit breaker escalates on evidence.
- **Peer offline; attacker impersonates via mesh routing**: substrate cannot verify peer identity if peer is truly unreachable, but attacker's signatures still must chain-verify against known Genesis. Absent peer signatures cannot be forged.

## Non-goals

- **Not a global reputation system**. Reputation per DISTRIBUTED-KNOWLEDGE-COMMONS composes with trust anchor but doesn't replace it. Substrate does not maintain global peer trustworthiness scores.
- **Not automatic trust bootstrap**. New peers don't get default trust. Every peer trust anchor requires operator ceremony. Bootstrap of new sovereigns into mesh happens via direct address exchange or referral from trusted peer, not via automatic discovery + trust.
- **Not federation-level authority**. Trust anchors are per-sovereign. There is no "trusted-by-the-federation" status. Each operator declares their own trust anchors.
- **Not a certificate authority model**. Substrate does not run a CA. Peer identities are Genesis-derived per each peer's sovereign root, not certified by a central authority.

## Open positions

- **Trust anchor discovery UX**. Operator needs to see and manage their trust anchors. Dashboard panel? CLI verb? Regent-narrated summary? Design work.
- **Bootstrapping semantics**. First peer trust anchor for a fresh sovereign — how does the operator find any peer to trust? Reference index? Bootstrap ceremony with foundation-published peers? Community discovery?
- **Depth policy defaults**. What's the sensible default depth for a new trust anchor grant? Auto-admit is convenient but higher-risk; review-required is safer but more operator work.
- **Trust anchor decay**. Should trust anchors slowly decay over time without positive reinforcement? Trade-off: operator effort vs safety.
- **Multi-anchor peer**. Operator grants multiple surface-scoped trust anchors to one peer (chain-admission + extension-admission + observation-reference). Should there be a "meta-trust" summary? Or are they always independent?
- **Peer collectives**. Some peer relationships are with collectives (per COLLECTIVE-ADOPTION-ARCHITECTURE-2026-07.md), not individual sovereigns. How does trust anchor apply to a collective peer? Currently: trust anchor is per-sovereign; collective interactions route to individual sovereigns per Decision D.
- **Rate limits on trust anchor changes**. Should substrate rate-limit trust anchor grants/revokes to prevent ceremony-based DoS or manipulation? Probably yes with reasonable defaults.

## What composes from here

Immediate design work:

1. **Trust anchor receipt schemas** — Layer B canonical spec for grant/adjust/revoke/rotation-update receipts
2. **Surface-specific admission integration** — for each of the six trust surfaces, how the trust anchor is queried and applied
3. **Reputation composition rules** — declared per surface for how reputation modulates precedent
4. **Peer rotation handling flow** — operator UX for reviewing peer rotations
5. **Ongoing observation policy** — what patterns trigger officer proposals to adjust trust anchors

Near-term implementation:

1. Trust anchor storage and query runtime in `crates/zp-server/src/peer_trust/`
2. Chain-anchored trust anchor state management
3. Surface-specific admission-check integration (Quarantine Plane peer surface, extension admission, observation materialization, commitment endorsement)
4. Peer rotation observer — watches for rotation notifications and presents to operator
5. Dashboard panel for trust anchor management (list anchors, review pending peer rotations, adjust depths)
6. CLI verbs: `zp peer trust grant|adjust|revoke|list`

## Framing note

Peer trust anchor management is the substrate's structural discipline for peer-facing surfaces. Same principle as delegation for internal capabilities, delegable safety for restrictions, and observation-scope delegation for observation surfaces — extended to peer relationships.

The load-bearing insight: **trust across sovereigns is per-surface, chain-anchored, and operator-declared.** Not implicit. Not vendor-decreed. Not derivable from reputation alone. The operator explicitly declares which peers to trust for which surfaces at which depth, and the substrate enforces structurally. Reputation accelerates precedent within anchor bounds but does not create trust where anchor is absent.

Combined with the substrate's structural discipline across every trust boundary — actions, admissions, observations, cognition, extensions, hardware, emergency response, Genesis rotation — peer trust anchor completes the trust envelope for federated substrates. Every trust decision — internal or peer-facing — chain-anchored, Genesis-derived, structurally enforced, delegable via ceremony. Same discipline; different scope; one canonical trust model that extends coherently from the operator's sovereign root to the mesh they participate in.
