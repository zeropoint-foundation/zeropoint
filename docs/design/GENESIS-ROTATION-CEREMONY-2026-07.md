# Genesis Rotation Ceremony

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` Part XI (Genesis Ceremony) with the specific case of *rotating* a Genesis root — the ceremony flow for replacing a compromised, aging, or lost Genesis with a new one while preserving substrate identity continuity. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `KEEL-2026-07.md` (§II.5 Genesis-as-single-root, Part VII Peer-Verification Contract, Part XI Genesis Ceremony), `SUBSTRATE-FORM-2026-07.md` (form graduation ceremony shape), `CIRCUIT-BREAKER-2026-07.md` (Genesis compromise as the bigger emergency), `BLAST-RADIUS-AND-RECOVERY-2026-07.md` (forward-only recovery discipline).

## Framing

Genesis is the substrate's single sovereign root per KEEL §II.5. Every key derives from it, every signature traces to it, every trust decision anchors on it. That makes Genesis the load-bearing failure point: if Genesis is compromised, every derived authority is compromised. If Genesis is lost, the sovereign's chain-anchored substrate becomes read-only forever.

The Genesis rotation ceremony is the substrate's structural discipline for handling these edge cases without destroying substrate identity continuity. Rotation preserves the sovereign's identity (same operator, same chain history, same trust corpus) while transitioning the cryptographic root from an old keypair to a new one. Old signatures remain valid as historical evidence; new signatures use the new root; a chain-anchored transition receipt marks the boundary.

Three properties frame the ceremony:

1. **Rotation preserves identity, not just keys.** The sovereign's identity — chain history, delegation precedent, learned trust patterns, community reputation — is preserved. What changes is the current signing authority. Historical signatures under the old Genesis remain valid evidence of what happened when the old Genesis was authoritative.
2. **Rotation is chain-anchored and irreversible.** The transition itself is a ceremony receipt on the chain. Old Genesis emits its final signature — the transition ceremony — attesting to the new Genesis's identity. New Genesis takes over from that receipt forward. No "undo" once the transition receipt lands.
3. **Rotation is the fallback for compromises that break lower-level mechanisms.** When circuit breaker cannot contain the compromise, when quarantine cannot filter out the attacker, when the observer's own key is suspect — rotation is the response. It's the biggest hammer in the safety envelope, used deliberately.

## When rotation is required

Four distinct trigger scenarios:

### Compromise-suspected rotation

Attacker has (or is suspected to have) the operator's Genesis material. Old Genesis can no longer be trusted for any future authority. Immediate rotation required.

Triggers:
- Physical hardware token loss (YubiKey/Nitrokey/Trezor lost or stolen)
- Suspected key extraction (hardware analysis attack, cold-boot RAM recovery)
- Detected anomalous Genesis signatures on chain (operator sees receipts they didn't sign)
- Firmware compromise on hardware Genesis token that could have exposed keys

Ceremony priority: emergency. Old Genesis is revoked as fast as possible.

### Preventive rotation

Genesis material is intact and operator-controlled, but cryptographic hygiene suggests rotation.

Triggers:
- Genesis is N years old and cryptographic best-practice suggests rotation
- Cryptographic algorithm (Ed25519) is superseded by newer algorithm; substrate migration to new algorithm
- Operator wants to migrate from software Genesis to hardware token Genesis (or between hardware token vendors)
- Operator wants to move from single-signature Genesis to M-of-N quorum Genesis (or vice versa)

Ceremony priority: normal. Deliberate scheduled operation, not emergency.

### Recovery rotation (M-of-N quorum)

Operator has lost access to Genesis but has pre-registered recovery tokens per Decision A's quorum sovereignty design.

Triggers:
- All copies of Genesis material lost
- Hardware Genesis token damaged beyond recovery
- Operator incapacitated; heirs invoking recovery quorum

Ceremony priority: recovery. Requires M-of-N recovery ceremony from pre-registered recovery tokens.

### Migration rotation

Substrate is graduating between Forms (Companion → Appliance → Sovereign) and operator chooses to establish new Genesis at higher-sovereignty Form as part of graduation.

Triggers:
- Operator graduating from Companion Form (vendor-hosted keys) to Sovereign Form (hardware token Genesis)
- Operator standing up dedicated hardware Genesis for the first time
- Operator moving Genesis from one hardware token to another for hardware upgrade

Ceremony priority: planned. Composes with Form graduation ceremony.

## Ceremony steps

Four-phase ceremony sequence. Each phase is chain-anchored via specific receipts.

### Phase 1 — Preparation

**Old Genesis attestation**: operator emits `genesis:rotation:initiated:<rotation_id>` receipt signed by OLD Genesis, declaring intent to rotate. Fields:
- Rotation reason (compromise-suspected / preventive / recovery / migration)
- Timestamp
- Expected new Genesis public key (if known before ceremony)
- Rotation ceremony ID

If compromise is suspected, this phase may be skipped — attacker may prevent the operator from signing. In that case, recovery ceremony takes over.

**New Genesis provisioning**: operator generates new Genesis material.
- Hardware token path: touch new YubiKey/Nitrokey/Trezor; generate Ed25519 keypair on device; extract public key
- Software fallback path: cryptographically-secure key generation with immediate storage in operator-controlled encrypted vault
- M-of-N quorum path: distributed key generation ceremony with N signers

Emit `genesis:new_key_provisioned:<rotation_id>` receipt signed by OLD Genesis (or by recovery quorum), attesting to the new Genesis public key. This receipt is the cryptographic bridge — it links the old identity to the new identity via a signature only the old could produce.

For compromise-suspected rotation where old Genesis is unavailable: the recovery quorum provides the bridging signatures instead.

### Phase 2 — Transition ceremony

**Bridging receipts**: for each substrate-critical piece of state, emit transition receipts:

- `genesis:transition:vault_reencryption:<rotation_id>` — vault entries currently encrypted under keys derived from OLD Genesis are re-encrypted under keys derived from NEW Genesis. Old vault entries remain accessible for post-rotation forensics; new vault entries use new keys. Signed by OLD Genesis (or recovery quorum).
- `genesis:transition:delegation_cascade:<rotation_id>` — active delegations currently signed under OLD Genesis get re-signed under NEW Genesis. Old delegations remain valid historical evidence but are revoked forward. Chain records both.
- `genesis:transition:officer_reprovisioning:<rotation_id>` — officer signing keys re-derived from NEW Genesis. Old officer keys are Genesis-certified under old Genesis (chain history); new officer keys are Genesis-certified under new Genesis.
- `genesis:transition:observer_reprovisioning:<rotation_id>` — hardware self-observer keys re-derived. Requires physical interaction with each observer (touching the board's provisioning switch or connecting via UART for re-provisioning). Any observer that cannot be reached is arrested (circuit breaker) until rotation completes for it.
- `genesis:transition:cognitive_key_reprovisioning:<rotation_id>` — cognitive input plane and cognitive self-observer keys re-derived.

**All bridging receipts are signed by OLD Genesis** (or by the recovery quorum). This is the ceremony's cryptographic gravity: the OLD Genesis attests to the NEW Genesis's authority to hold each specific role.

If OLD Genesis is unavailable (compromise scenario), recovery quorum performs the bridging signatures per Decision A.

### Phase 3 — Handover

**Handover receipt**: the culminating signature. Signed by both OLD Genesis (or recovery quorum) AND NEW Genesis. Fields:
- Rotation ID
- OLD Genesis public key
- NEW Genesis public key
- Set of transition receipts under this rotation (hashes)
- Effective timestamp (from this point forward, NEW Genesis is authoritative)

Emit as `genesis:handover:completed:<rotation_id>`. This is the chain's cryptographic evidence of the transition. From this receipt forward, all authority derives from NEW Genesis. OLD Genesis has no future authority (any signature under OLD Genesis after this receipt is invalid).

### Phase 4 — Verification

**Post-rotation verification**: substrate self-verifies that rotation completed correctly:
- All active delegations trace to NEW Genesis
- Vault entries decrypt with NEW Genesis-derived keys
- Officer signatures verify under NEW Genesis
- Observer heartbeats resume with NEW Genesis-derived signatures
- Cognitive discipline sandwich (Cognitive Input Plane, Cognitive Self-Observer, Claim Verifier) operates with NEW Genesis

Emit `genesis:rotation:verified:<rotation_id>` receipt on successful verification. If verification fails at any component, emit `genesis:rotation:incomplete:<rotation_id>` with what failed and circuit-break to substrate-wide graduated response until operator investigates.

## Chain history preservation

Genesis rotation preserves the sovereign's chain history. This is load-bearing.

**Old signatures remain valid evidence.** A receipt signed by OLD Genesis at time T (before rotation) is valid evidence that OLD Genesis signed it at time T. That signature does not become invalid retroactively when Genesis rotates. Chain integrity depends on this — invalidating history would break the append-only property.

**Old delegations are historical, not currently-active.** A delegation signed by OLD Genesis before rotation was authoritative at that time. After rotation, that delegation is superseded by any equivalent NEW-Genesis-signed delegation and is otherwise treated as expired. But the historical record shows: at time T, operator delegated capability X to actor Y under OLD Genesis authority.

**Precedent under OLD Genesis remains precedent.** The trust corpus accumulated under OLD Genesis carries forward. Regent's autonomous action envelope, learned patterns, community reputation — none of these are reset by rotation. The chain-anchored precedent is preserved; only the current-authority-signing changes.

**Peer sync sees continuity.** For peers who trust the sovereign's identity, the rotation is a chain event they observe. They update their trust anchor for this sovereign from OLD Genesis to NEW Genesis based on the handover receipt. Peers verify the handover was signed by OLD Genesis (or recovery quorum) — if it was, they accept the transition.

## Peer notification

For federated substrates (sovereigns in a mesh), rotation is a peer-relevant event.

**Peer notification receipt**: after handover, emit `genesis:rotation:peer_notification:<rotation_id>` receipt intended for peer distribution. Peers receiving this receipt:
- Verify the receipt chain-integrates with the sovereign's chain
- Verify the handover receipt is signed by the sovereign's previously-known Genesis
- Update their local peer trust anchor for this sovereign from OLD Genesis to NEW Genesis
- Emit their own `peer:trust_anchor_updated:<sovereign_id>:<new_genesis>` receipt as chain-anchored evidence of their trust update

Peers who reject the transition (because they suspect the OLD Genesis was compromised before the handover signature) don't update their trust anchor — they treat the sovereign as unknown-identity from that point until they can independently verify the transition legitimacy.

## Attack model

Attacker scenarios and how the ceremony addresses them:

- **Attacker has OLD Genesis, tries to forge a rotation to attacker-controlled key**: attacker can sign a rotation transition. But operator sees the rotation ceremony ceremony on chain and can invoke recovery quorum to override. Whichever ceremony (attacker's or recovery quorum's) lands first is authoritative; race condition favors detection since attacker's rotation would be visible to operator immediately via observation plane / cognitive input plane at Tier 1.
- **Attacker races the operator during rotation**: rotation involves multiple sequential receipts. Attacker's forged rotation must land coherently. Any inconsistency in the transition receipt chain (missing bridging receipts, mismatched signatures) invalidates the rotation. Verification phase catches inconsistencies.
- **Attacker has partial recovery quorum shares**: rotation via recovery requires M-of-N shares. Attacker with fewer than M shares cannot initiate rotation. If attacker gains M shares, that's Genesis compromise scenario, and recovery quorum threshold M was chosen too low. Threshold selection is operator's judgment.
- **Attacker prevents rotation by blocking Genesis material access**: physical hardware token prevents this for the token-holding path. For software Genesis, physical operator control of the storage location prevents this. If attacker has extraction access, that's the Genesis compromise trigger anyway.
- **Attacker manipulates chain history during rotation**: chain integrity is verified at every step. Any hash-linkage failure during rotation ceremony invalidates the ceremony and triggers circuit breaker.
- **Attacker impersonates the sovereign to peers with faked rotation receipt**: peers verify chain-integration; faked receipts don't chain-verify. Peers may temporarily see the sovereign as offline while they investigate, but they don't accept an unverifiable rotation.
- **Attacker exploits post-rotation before verification**: verification phase runs before rotation is chain-declared "completed." If exploitation happens before verification, verification catches it and rotation is marked incomplete.

## Failure modes

- **Rotation incomplete**: verification fails; some substrate component doesn't accept new Genesis. Substrate enters emergency graduated response until operator remediates. Old Genesis remains authoritative for components that haven't transitioned; substrate operates in split state until resolved.
- **Recovery quorum insufficient**: fewer than M recovery tokens present. Cannot rotate. Sovereign identity is preserved via chain but no forward authority possible. Operator must either recover additional tokens or accept that this sovereign identity is read-only.
- **Peer disagreement**: some peers accept the transition; others reject. Sovereign appears with dual identity in the mesh temporarily; peer coordination convergence works this out via reputation and further evidence.
- **Attacker succeeds in racing**: attacker's forged rotation lands before operator's. Operator recovery ceremony can supersede — the sovereign then has three rotations: initial (unauthorized attacker), operator recovery (invalidating attacker's), operator's new stable rotation. Chain shows the full sequence; peers can reason about which authority to trust based on evidence.

## Composition with existing substrate discipline

**Composition with SUBSTRATE-FORM**: Genesis rotation is a Form-affecting event when it changes Genesis storage (Companion Form soft Genesis → Sovereign Form hardware Genesis). Rotation ceremony can be bundled with Form graduation ceremony.

**Composition with CIRCUIT-BREAKER**: Genesis rotation may be triggered by extreme circuit breaker escalation — when the substrate detects compromise so deep that trusting current Genesis is not viable. Circuit breaker at substrate-wide level can require rotation as reset condition.

**Composition with BLAST-RADIUS-AND-RECOVERY**: rotation is forward-only. Old Genesis-signed history is preserved as truth. Recovery from rotation means substrate resumes operations under new Genesis, not rolling back to before rotation.

**Composition with QUARANTINE-PLANE**: post-rotation, extensions previously admitted under OLD Genesis remain admitted (their admission delegations are historical). Operator may choose to explicitly revoke or re-admit under NEW Genesis via ceremony. Silent auto-revocation would break operational continuity.

**Composition with COGNITIVE-INPUT-PLANE**: standing corrections and commitments emitted under OLD Genesis remain valid input for Regent. NEW Genesis-signed corrections supersede when they conflict.

**Composition with hardware self-observer (per HARDWARE-OBSERVER-2026-07.md)**: observer's per-board provisioning requires physical interaction to accept new Genesis. Any observer not re-provisioned is arrested (circuit breaker) until rotation completes for its board.

## Non-goals

- **Not a routine operation**. Genesis rotation is deliberate and rare. Substrate should not encourage frequent rotation; each rotation has ceremony cost, verification cost, and peer disruption.
- **Not a bypass for operational discipline**. Rotation cannot substitute for proper delegation management, credential hygiene, or emergency response. Rotation is the last-resort ceremony when other mechanisms don't apply.
- **Not automated**. No trigger source can auto-invoke Genesis rotation. Even circuit breaker at maximum escalation can only *require* operator ceremony; it cannot execute rotation itself.
- **Not reversible**. Chain records the transition permanently. No "cancel rotation" ceremony exists; if operator changes their mind mid-rotation, they must complete the ceremony and then rotate again.

## Open positions

- **Verification phase timing**. Post-handover verification takes some time (each component checks that new Genesis works). During verification, what state is the substrate in? Reduced-authority interim? Full new-Genesis authority? Choice affects operational continuity vs safety.
- **Peer notification cadence**. Some peers may be offline during rotation. When does peer notification retry? What's the maximum tolerance for peer synchronization delay? Depends on mesh characteristics.
- **Vault re-encryption discipline**. Re-encrypting the vault is expensive for large vaults. Can we lazily re-encrypt (entries re-encrypt on next access)? Trade-off: security vs operational cost.
- **Recovery threshold defaults**. Decision A commits to M-of-N recovery quorum. What are reasonable defaults for M and N? 2-of-3 for most operators? Custom per operator judgment.
- **Multi-device rotation coordination**. Sovereign with multi-device fleet: does rotation happen on one device and propagate, or all devices simultaneously? Trade-offs around consistency and coordination complexity.
- **Rotation frequency limits**. Should substrate rate-limit rotation ceremonies to prevent ceremony-based DoS? Probably yes with some threshold; needs empirical tuning.

## What composes from here

Immediate design work:

1. **Rotation receipt schemas** — Layer B canonical spec for each phase's receipts
2. **Recovery quorum receipt schema** — how M-of-N shares combine for bridging signature
3. **Peer notification protocol** — chain-anchored peer trust anchor updates
4. **Verification checklist** — per substrate component, what verification looks like
5. **Operator UX** — dashboard flow for initiating rotation, dashboard flow for observing rotation-in-progress, dashboard flow for verification review

Near-term implementation:

1. Rotation runtime in `crates/zp-server/src/genesis_rotation/`
2. Vault re-encryption utility
3. Delegation cascade utility for re-signing active delegations
4. Officer/observer/cognitive-key reprovisioning per-component logic
5. Peer notification distribution over mesh
6. Recovery quorum interface for M-of-N ceremonies

## Framing note

Genesis rotation is the substrate's fallback for compromises that break lower-level mechanisms. Circuit breaker contains normal emergencies; quarantine filters new attacks; observer detects hardware anomalies. Rotation is the ceremony for when Genesis itself — the sovereign root — needs to change while preserving substrate identity continuity.

The load-bearing insight: **rotation preserves identity, not just keys.** Chain history remains truth; historical signatures remain valid evidence; precedent under old Genesis continues to inform Regent's autonomous scope under new Genesis; peer trust anchor updates via chain-anchored transition. What changes is the current signing authority, not the sovereign's identity or their accumulated trust corpus.

Combined with the substrate's structural discipline across every trust boundary — actions, admissions, observations, cognition, extensions, hardware, emergency response — Genesis rotation completes the response envelope for even the deepest compromise scenarios. Sovereignty is preserved because the operator remains authoritative through the transition; safety is preserved because the ceremony is chain-anchored, verifiable, and Genesis-derived at every step; continuity is preserved because chain history is truth that survives any legitimate rotation.
