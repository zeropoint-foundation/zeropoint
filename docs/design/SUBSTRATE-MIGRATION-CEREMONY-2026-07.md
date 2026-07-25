# Substrate Migration Ceremony

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), §II.14 (Substrate Realization), §III.20 (forward-only recovery), Part VII (Peer-Verification Contract), Part XI (Genesis ceremony), Part XIV (Substrate Realization tiers). Specifies chain-preserving ceremonies for moving substrate between hardware, between Forms, or between physical locations while preserving Genesis authority, chain integrity, and operational continuity. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `SUBSTRATE-FORM-2026-07.md` (Form graduation is one class of migration; also non-Form-changing migrations), `GENESIS-ROTATION-CEREMONY-2026-07.md` (migrations that require new Genesis compose with rotation), `BUILD-PROCESS-DESIGN-2026-07.md` (build lifecycle receipts anchor migrated substrate's provenance), `PEER-TRUST-ANCHOR-2026-07.md` (peers verify migrated substrate identity continuity), `OPERATOR-DEATH-AND-LEGACY-2026-07.md` (posthumous archival migration for chain preservation), `RECOVERY-CEREMONY-UX-2026-07.md` (some migrations compose with Form-graduation recovery).

## Framing

Substrate is not permanently bound to specific hardware. Operators change devices, upgrade Forms, relocate physical infrastructure, retire aging hardware, split single-node installations into multi-device fleets, or consolidate fleets into single nodes. Each of these is a *migration* — a transition of substrate operation from one physical/logical instantiation to another while preserving the sovereignty, chain, and operational continuity.

Referenced across SUBSTRATE-FORM (Form graduation ceremony), GENESIS-ROTATION-CEREMONY (rotation-during-migration), BUILD-PROCESS-DESIGN (build lifecycle across migration), and PEER-TRUST-ANCHOR (peer verification of migrated identity) — but no single spec has covered the migration ceremony itself. This spec fills that gap.

Three properties frame the ceremony:

1. **Chain is portable; identity is preserved.** Chain is truth about the operator's substrate operations; it travels with the operator. Genesis authority is preserved across migration — Genesis token accompanies the operator physically or logically per the migration class. Migration does not create new sovereignty; it moves existing sovereignty to new operational context.
2. **Every migration is a chain-anchored ceremony.** Migration receipts document what moved, from where, to where, when, and under what verification. Peers observe migrations via chain distribution. Migration is not silent hardware swap; it is documented substrate lifecycle event.
3. **Migration classes vary in scope and ceremony.** Simple device replacement is lighter ceremony than Form graduation; posthumous archival migration is different again from operator-initiated relocation. Spec covers migration classes explicitly with class-appropriate ceremony.

## Migration classes

Six canonical migration classes with distinct ceremony shapes:

### Class 1 — Same-Form hardware replacement

Operator replaces substrate hardware while remaining on same Substrate Form. Example: Sovereign Form on Pi 5 upgrading to Pi 6; Companion Form on macOS moving to newer Mac; Appliance Form dedicated hardware swapping out failing SBC.

Genesis: unchanged. Same Genesis material moves to new hardware (typically hardware token accompanies operator; software Genesis is transferred via encrypted transfer ceremony).

Chain: unchanged. Full chain migrates to new hardware. New hardware becomes the primary substrate host.

Ceremony scope: moderate. Verification of new hardware, chain integrity confirmation post-transfer, peer notification.

### Class 2 — Cross-Form graduation

Operator moves from one Substrate Form to another. Composes with SUBSTRATE-FORM's Form graduation ceremony.

Legal transitions per KEEL Part XIV: Companion → Appliance, Appliance → Sovereign, Companion → Sovereign, and reverse paths (though reverse degrades sovereignty reach).

Genesis: may change (Companion to Sovereign typically involves new hardware Genesis token provisioning; Sovereign to Companion may preserve or retire hardware Genesis per operator choice).

Chain: unchanged; migrates to new Form. Form-specific state may be reprovisioned.

Ceremony scope: substantial. Composes with Form graduation ceremony from SUBSTRATE-FORM and potentially Genesis rotation ceremony from GENESIS-ROTATION.

### Class 3 — Multi-device fleet expansion

Operator adds a new device to their fleet. Per Decision C (Regent-follows-the-operator), each device in the fleet is a scoped delegation from Genesis.

Genesis: unchanged. New device receives scoped delegation via Genesis-signed device provisioning ceremony.

Chain: replicated across fleet. New device gets initial chain sync.

Ceremony scope: moderate. Device provisioning, chain sync, peer awareness of the expanded fleet.

### Class 4 — Multi-device fleet contraction

Operator removes device from fleet. May be retirement of aging device, disposal of failed hardware, migration to smaller device count.

Genesis: unchanged.

Chain: preserved on remaining fleet. Retired device's local chain copy verified before device retirement; scoped delegation revoked.

Ceremony scope: moderate. Delegation revocation, chain verification on remaining fleet, physical hardware disposition.

### Class 5 — Physical relocation

Operator physically relocates substrate hardware (moving residence, moving office, taking substrate on travel). Substrate operational context changes but hardware and Form are unchanged.

Genesis: unchanged.

Chain: unchanged; travels with substrate.

Ceremony scope: light. Chain-anchored relocation notice; peer notification for peers who care about geographic context (some peers may adjust trust anchor scoping based on jurisdictional changes).

### Class 6 — Posthumous archival migration

Per OPERATOR-DEATH-AND-LEGACY hardware disposition: operator has died; chain being migrated to archival hosting per legacy declarations.

Genesis: no forward authority; operator's Genesis retired.

Chain: preserved in memorial-sovereign state at archival host per operator's declared preference.

Ceremony scope: substantial. Composes with OPERATOR-DEATH-AND-LEGACY hardware disposition. Executor authority governs.

## Ceremony steps by class

Different classes require different ceremony steps. Common structural pattern below, with class-specific variations.

### Common Phase A — Pre-migration declaration

Operator (or executor for posthumous class) declares migration intent via chain-anchored ceremony.

Emit `migration:initiated:<migration_id>` receipt with:
- Migration class
- Source substrate identifier
- Target substrate identifier
- Genesis handling (unchanged, rotated, retired)
- Chain handling (transferred, replicated, archived)
- Timing (immediate, scheduled)
- Verification requirements

Signed by operator's Genesis (or executor under scope for posthumous class).

### Common Phase B — Target preparation

Target substrate prepared for migration:

- Hardware verification per Substrate Form requirements
- Firmware attestation per HARDWARE-COMPROMISE-EVIDENCE where applicable
- Boot chain verification
- Storage provisioning
- Network readiness

Emit `migration:target_prepared:<migration_id>` receipt.

### Common Phase C — Chain transfer

Chain content transferred from source to target substrate. Transfer methods vary:

- **Direct transfer**: source substrate emits chain content via secure channel to target substrate; target verifies content integrity via hash-linkage validation
- **Backup restoration**: chain restored from operator-controlled backup; source substrate not required to be online
- **Peer-mediated**: chain content replicated via peer distribution; target substrate reconstructs from peer-hosted replicas

Each method has integrity verification steps. Emit `migration:chain_transferred:<migration_id>:<method>` receipt with chain-tail hash confirmation.

### Common Phase D — Identity attestation

Genesis handling per migration class:

- **Genesis unchanged**: source Genesis material becomes target Genesis material (hardware token physical transfer, or software Genesis encrypted transfer). Chain evidence of Genesis continuity emitted.
- **Genesis rotated**: composes with GENESIS-ROTATION ceremony. New Genesis provisioning, transition receipts, handover receipt.
- **Genesis retired**: (posthumous class) no new forward authority; substrate enters memorial-sovereign state.

Emit `migration:identity_attested:<migration_id>` receipt.

### Common Phase E — Fleet delegation update (multi-device classes)

For fleet expansion/contraction: scoped delegation receipts issued for new devices or revoked for retired devices per Decision C.

- Expansion: `device:delegation_granted:<device_id>:<scope>` receipts
- Contraction: `device:delegation_revoked:<device_id>` receipts

### Common Phase F — Peer notification

Federated peers notified of migration. Peers verify migration receipts against operator's known Genesis (or handover if Genesis rotated); update their trust anchors for the operator to reflect the new substrate configuration.

Peers emit `peer:migration_acknowledged:<sovereign_id>:<migration_id>` receipts on their own chains.

### Common Phase G — Cutover

Migration becomes authoritative. Target substrate becomes primary; source substrate transitions per operator declaration:

- **Retired**: source hardware retained but no longer signs. Preserves as historical artifact or gifted per operator choice.
- **Archived**: source hardware transferred to archival host with chain read-only.
- **Destroyed**: source hardware physically destroyed after chain replication confirmation.
- **Continued as fleet member**: source remains active in reduced role (e.g., after fleet expansion, source may become secondary device).

Emit `migration:cutover:<migration_id>` receipt.

### Common Phase H — Verification and completion

Target substrate self-verifies health:

- Chain integrity verified
- Officer heartbeats confirmed
- Extensions transitioned (per Class-specific handling)
- Peer sync operating
- Cognitive layer operational

Emit `migration:verified:<migration_id>` and `migration:completed:<migration_id>` receipts. Migration ceremony closes.

## Chain integrity during transfer

Chain is critical asset; migration must preserve integrity. Structural safeguards:

- **Hash-linkage validation**: target substrate validates hash-linkage of received chain against source substrate's declared chain-tail. Broken linkage aborts migration with verification failure.
- **Signature verification**: all received receipts verified against operator's Genesis (and appropriate delegated signers).
- **Content-address confirmation**: content-addressed evidence bundles verified against their hashes.
- **Peer cross-verification**: for critical migrations, peers can cross-verify chain content via distributed comparison.

Migration failure at chain-integrity check: chain rollback to pre-migration state on source; target discards partial chain; migration ceremony emits `migration:failed:<migration_id>:<reason>` receipt.

## Genesis handling during migration

Genesis is the sovereign root; its handling during migration is load-bearing.

### Same-Genesis migration (Classes 1, 3, 4, 5)

Genesis material physically or logically travels with operator. On hardware token: token accompanies operator to new hardware. On software Genesis (Companion Form): encrypted transfer via operator-controlled channel.

Attestation: source substrate emits `genesis:transfer_completed:<migration_id>` receipt confirming Genesis material has left source's custody; target substrate emits `genesis:custody_established:<migration_id>` receipt confirming reception. Chain evidence of continuity.

### Genesis rotation migration (Class 2 sometimes)

Some cross-Form graduations involve new Genesis (Companion Form soft Genesis → Sovereign Form hardware Genesis, for example). Composes with GENESIS-ROTATION-CEREMONY. Both ceremonies compose into unified migration+rotation ceremony.

### Genesis retirement migration (Class 6)

Posthumous archival; no new Genesis. Operator's Genesis retired via death declaration (per OPERATOR-DEATH-AND-LEGACY). Chain moves to memorial-sovereign state at archival host.

## Composition with existing specs

- **SUBSTRATE-FORM**: Class 2 (cross-Form graduation) composes with Form graduation ceremony. Migration spec provides the chain-preservation and identity-continuity mechanics; Form graduation provides the Form-specific ceremony.
- **GENESIS-ROTATION-CEREMONY**: migrations requiring new Genesis compose with rotation. Handover receipts serve both migration and rotation ceremonies.
- **BUILD-PROCESS-DESIGN**: post-migration, substrate's build lifecycle continues on new hardware. Chain records the migration alongside builds; peer verification composes.
- **PEER-TRUST-ANCHOR**: peers verify migration and update their trust anchors. Peer notification receipts document acknowledgment.
- **OPERATOR-DEATH-AND-LEGACY**: Class 6 (posthumous archival) is a specific migration under executor authority. Death ceremony precedes migration ceremony.
- **RECOVERY-CEREMONY-UX**: operator UX for migration ceremonies composes with recovery UX patterns — chain-anchored ceremony state, Regent narration, dashboard surfaces.
- **CHAIN-WATCHER-AND-COMMITMENTS**: chain-watchers for the migration ceremony fire on transitions, allowing operator or peers to react to specific migration events.

## Attack model

- **Attacker attempts to impersonate migrated substrate**: migration receipts require operator Genesis signature. Attacker without Genesis cannot forge migration; peers verify against known operator Genesis.
- **Attacker exploits migration window to substitute their own Genesis**: Genesis handling receipts explicit and chain-anchored. Genesis substitution requires either operator ceremony (which operator would notice) or Genesis compromise (handled by Genesis rotation ceremony).
- **Attacker interrupts chain transfer to cause partial migration**: hash-linkage validation catches partial transfers. Failed migration emits explicit failure receipt; substrate rolls back to pre-migration state.
- **Attacker corrupts target substrate before cutover**: target verification phase catches corruption. Migration doesn't cut over until target passes verification. Attacker successful only if verification is compromised, which requires broader substrate compromise.
- **Attacker exploits peer trust anchor gap during migration**: peers acknowledge migration only after chain-verifying migration receipts. Peer's own trust anchor discipline holds during migration; peers don't accept unverified new substrate identity.
- **Attacker uses migration to escape circuit breaker state**: circuit breaker state travels with chain. Migration to new hardware doesn't reset circuit breaker; escalations remain until proper reset ceremony.
- **Attacker manipulates fleet delegation during expansion**: device delegations chain-anchored per operator Genesis. Unauthorized device provisioning doesn't verify.

## Failure modes

- **Migration incomplete due to hardware failure**: source or target hardware fails mid-migration. Chain state at failure point preserved on source; target discarded; failure receipt emitted; operator can retry with different target hardware.
- **Chain integrity verification failure**: partial or corrupted chain transferred. Migration aborts; source preserved intact; operator investigates transfer method and retries.
- **Peer verification failures**: some peers fail to verify migration; sovereign appears with dual identity in the mesh temporarily. Peer convergence via chain evidence and additional operator ceremony if needed.
- **Extension incompatibility with target hardware**: some extensions may not run on target platform (Companion Form to Sovereign Form on ARM if extensions are x86-specific). Migration proceeds; incompatible extensions concluded per EXTENSION-SURFACE lifecycle.
- **Cognitive layer transition drift**: Regent's cognitive context may include hardware-specific state that doesn't transfer cleanly. Regent transitions with chain-anchored state; may need brief re-attunement post-migration.
- **Insufficient storage on target**: target substrate storage inadequate for chain size. Migration aborts pre-transfer; operator provisions larger storage or archives older chain content per operator ceremony.
- **Regulatory friction (cross-jurisdiction physical migration)**: some jurisdictions have data residency requirements. Substrate does not automatically comply with jurisdiction-specific regulation; operator responsibility.

## Non-goals

- **Not automated migration**. Every migration requires operator ceremony. Substrate does not autonomously migrate itself.
- **Not universal cross-Form compatibility**. Some Form transitions are cleaner than others; some may require operator investment in reconfiguration.
- **Not chain content transformation**. Chain content is preserved verbatim across migration; substrate does not re-encode, re-encrypt (unless Genesis rotation), or re-structure chain during migration.
- **Not extension migration guarantee**. Extensions may or may not survive migration depending on target platform. Extension lifecycle per EXTENSION-SURFACE governs.
- **Not rollback of completed migration**. Once cutover completes and peer notifications propagate, migration is authoritative. To reverse, initiate new migration from target back to source-equivalent (or new) substrate.
- **Not zero-downtime migration**. Some migration classes involve operational discontinuity between source cutover and target activation. Operator UX surfaces expected downtime.

## Open positions

- **Chain transfer bandwidth requirements**: large chains take substantial time to transfer. Compression, incremental transfer for large chains, target-side reconstruction from peer-hosted content.
- **Chain content pruning during migration**: some operators may want to archive old chain content rather than transfer to smaller target hardware. Pruning ceremony under operator authorization.
- **Migration ceremony rehearsal mode**: practice migration without producing authoritative effects. Trade-off: educational value vs risk of false confidence.
- **Cross-vendor Genesis token migration**: operator upgrading YubiKey to Nitrokey to Trezor. Genesis rotation ceremony handles; UX for the specific hardware transition.
- **Fleet member as migration target**: existing fleet member becomes new primary vs new hardware becoming primary. Ceremony differs.
- **Peer trust anchor implications of jurisdiction change**: some peers may prefer to re-verify operator identity when operator relocates internationally.
- **Substrate archive federation**: for posthumous archival migration, federation of archival hosts. Reputation, capacity, longevity of archival service commitments.
- **Split migration**: single-substrate operator splits into multi-device fleet. Genesis remains one; each device gets scoped delegation.
- **Merge migration**: multi-device fleet consolidates into single substrate. Delegations retired; primary substrate absorbs full authority.

## What composes from here

Immediate design work:

1. **Per-class ceremony receipt schemas** — one for each migration class
2. **Chain transfer protocol** — secure channel, hash validation, incremental transfer
3. **Genesis handling protocol per class** — physical transfer, encrypted transfer, retirement
4. **Peer notification distribution** — migration receipts propagation
5. **Target verification protocol** — health checks post-migration

Near-term implementation:

1. Migration ceremony runtime in `crates/zp-server/src/migration/`
2. Per-class ceremony coordinators
3. Chain transfer utility
4. Genesis handling per class
5. Peer notification protocol
6. Dashboard migration panel (planned migrations, active migrations, migration history)
7. CLI verbs: `zp migration plan|initiate|verify|complete|history`

## Framing note

Substrate migration ceremony completes the substrate's lifecycle envelope for hardware transitions. Same principle as chain-anchored discipline elsewhere — chain is truth; ceremony precedes consequential changes; operator authorizes every consequential step; peers verify.

The load-bearing insight: **substrate is not permanently bound to specific hardware.** Operators change devices, upgrade Forms, relocate, retire aging hardware, expand and contract fleets. Each transition is a ceremony that preserves chain integrity, Genesis authority, and operational continuity. Chain travels with the operator; Genesis authority persists across migration (or is deliberately rotated as part of migration); peer trust anchors update to reflect the new substrate configuration. Migration is documented lifecycle event, not silent hardware swap.

Combined with the substrate's structural discipline across every trust boundary — actions, admissions, observations, cognition, extensions, hardware, emergency response, Genesis rotation, peer trust, build lifecycle, reproducibility, recovery UX, standing corrections, hardware compromise evidence, WiFi sensing, sovereign kinship, crisis response, shared-space etiquette, operator death and legacy, dependent sovereignty — substrate migration completes the hardware-lifecycle envelope. What was previously ad-hoc — "how do I move my substrate to a new device" — becomes structural: pre-migration declaration, target preparation, chain transfer with integrity verification, Genesis handling per class, peer notification, cutover, post-migration verification. Sovereignty is preserved because operator authorizes every step; safety is preserved because integrity is verified at every phase; continuity is preserved because chain travels with the operator and is documented at every transition.
