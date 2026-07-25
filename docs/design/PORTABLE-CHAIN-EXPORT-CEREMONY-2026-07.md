# Portable Chain Export Ceremony

**Document type:** Tier 2 canonical elaboration.
**Elaborates:** KEEL §II.5 (sovereign identity), §II.8 (chain-anchored evidence), §III.20 (forward-only recovery — chain is truth), §III.22 (evidence-based ceremony), Part VII (peer verification), Part XI (Genesis and rotation). Companion to `BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md` and `MULTI-DEVICE-OPERATION-2026-07.md`.
**Date:** 2026-07-18. Motivated by the SD-card-as-storage-medium discussion during Sovereign Form hardware planning: SD cards have real portability virtues (physically removable, cheap, cloneable) but real reliability limitations for live-chain writes under always-on operation. The composed answer — live chain on NVMe for reliability, portable snapshots on SD for the portability virtue — needs a ceremony.

**Author:** Ken Romero, with synthesis assistance from Claude.
**Status:** Living discipline. Small addition to existing anchor pipeline; composes cleanly with `epoch:anchored:N` receipts already in the substrate.

---

## Part I — What this addresses

The audit chain is the substrate's truth. On the operator's device, the chain lives on whatever medium the substrate is configured to write to — typically NVMe SSD in Sovereign Form Tier 0 or 1. This choice is right for reliability: NVMe handles always-on append-only writes cleanly, has capacitor-based power-loss protection, and survives unexpected reboots.

But the chain being tied to the device it lives on has real trade-offs:

- **Not physically portable.** Taking the chain with you means taking the device.
- **Not air-gappable.** The chain and the compute are the same medium.
- **Not trivially cloneable.** Multiple copies require multiple devices or extra tooling.

Chain-anchored evidence for the operator's history is the substrate's most valuable artifact — everything else (ontology, precedent, delegations, memory) derives from it. Losing physical access to that artifact — because the device is stolen, damaged, or geographically inaccessible — is a real sovereignty concern.

The portable-chain-export ceremony resolves this by producing chain-anchored **portable snapshots** on removable media (SD card, USB drive, any operator-controlled storage). Not a replacement for the live chain; a ceremonial export of chain state as of a specific epoch, verifiable independently of the substrate device.

**Failure class NOT addressed** (composes with other disciplines):
- Live-chain redundancy across devices — `MULTI-DEVICE-OPERATION-2026-07.md` handles fleet-level chain replication.
- Full backup and disaster recovery — `BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md` addresses recovery from device loss.
- Long-term archival — `OPERATOR-DEATH-AND-LEGACY-2026-07.md` addresses posthumous chain preservation.

Portable snapshots compose with all three but don't replace any.

---

## Part II — Composition with the existing anchor pipeline

The substrate already produces natural export boundaries via `epoch:anchored:N` receipts (per `crates/zp-server/src/anchor_pipeline.rs`). Every Merkle-sealed epoch is:

- A hash-linked snapshot of chain state up to sequence N.
- Independently verifiable — the Merkle root can be recomputed from the sealed range and compared.
- Chain-anchored — the seal itself is a receipt, so the "we sealed at epoch N" event is part of the chain.

This is the natural export unit. The ceremony extends the anchor pipeline with an optional "portable export" step at each epoch seal.

**Extension shape:**

```rust
// In anchor_pipeline.rs, at seal_epoch()
if operator_declared_portable_export_target.exists() {
    let export_result = write_portable_export(
        &sealed_epoch,
        &operator_declared_portable_export_target,
    );
    emit_receipt("chain:portable:exported", &export_result);
}
```

Every export is chain-anchored. The receipt cites: the epoch sequence, the target medium identifier (per operator-declared card ID), the export hash, whether the write succeeded.

---

## Part III — Ceremony flow

Six phases. Each produces chain-anchored evidence.

### Phase P0 — Operator declaration

Operator declares a portable export target via chain-anchored preference receipt:

```
chain:portable:target_declared
  card_id: string           # operator-assigned identifier for the medium
  mount_path: path          # where the substrate mounts it
  card_type: enum           # sd_card | usb_drive | external_ssd
  cadence: enum             # every_epoch | manual_only | daily | weekly
  operator_signature: bytes # Genesis-derived
```

Multiple targets can be declared simultaneously (e.g., primary SD card + off-site USB drive kept in a safe). Each has its own receipt and its own export cadence.

### Phase P1 — Epoch seal (existing)

The anchor pipeline seals epoch N as normal. Produces `epoch:anchored:N` receipt. This is unchanged by the ceremony; existing behavior preserved.

### Phase P2 — Portable export

If a declared target is currently mounted AND its cadence matches (every_epoch, or scheduled), the substrate writes the sealed epoch to the target medium.

Portable-medium file structure:

```
/<card_root>/
  zp-portable-chain/
    manifest.json                  # card metadata + operator Genesis pubkey
    epochs/
      000000.epoch                 # epoch 0 sealed data
      000001.epoch                 # epoch 1 sealed data
      ...
    signatures/
      000000.sig                   # operator signature over 000000.epoch
      ...
```

The `.epoch` file is the raw sealed epoch content (Merkle root + entries in the epoch's range). The `.sig` file is an operator-signed statement `("chain-export", epoch_N, epoch_root, card_id, timestamp)`. Chain from operator signature back to Genesis is embedded in `manifest.json`.

**Aligned blindness discipline applies to the export.** The exported epoch contains the same content as the source chain — subject to the same aligned-blindness disciplines already applied when the entries were originally chain-anchored. No blind-class data is on the source chain to begin with (per `SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md`), so no blind-class data reaches the portable medium.

### Phase P3 — Chain-anchor the export

The substrate emits `chain:portable:exported` receipt naming: the epoch exported, the target card_id, the write status, the SHA256 hash of the epoch file as written. This receipt is on the source chain — not the portable medium — so future chain readers can verify "epoch N was exported to card X at time T, with hash H."

### Phase P4 — Portable verification (independent path)

Anyone with the portable medium can verify its contents WITHOUT access to the source substrate:

1. Read `manifest.json` to obtain the operator Genesis public key.
2. For each `.epoch` file, verify the corresponding `.sig` file against operator signing key (chain in manifest.json shows key derivation from Genesis).
3. Verify each epoch's Merkle root by rehashing the epoch content.
4. Verify hash-link continuity across epochs (epoch N's first entry references epoch N-1's last entry hash).

If all checks pass, the portable medium contains an operator-signed, hash-linked, verifiable snapshot of chain state up to the last exported epoch. Not the live chain — a portable snapshot.

### Phase P5 — Portable-to-substrate reconciliation (recovery path)

If the operator recovers the substrate from a portable snapshot (device loss, disaster recovery), the ceremony's reverse flow:

1. Boot substrate on new device with Genesis material from sovereignty provider.
2. Substrate reads portable medium's `manifest.json` and verifies operator Genesis matches.
3. Substrate imports each epoch in sequence, verifying signatures and hash-links.
4. Live chain resumes from last exported epoch's tail entry.
5. Substrate emits `chain:portable:reconstituted` receipt naming the source card_id and epoch range imported.

**Gap discipline:** anything on the source substrate between the last exported epoch and the loss event is lost. Portable snapshots are chronological export, not real-time mirror. Operator sees the gap explicitly in chain evidence (the reconstituted receipt names the epoch imported; anything after that epoch on the original substrate is missing). Composes with `MULTI-DEVICE-OPERATION-2026-07.md` — for real-time redundancy, use fleet chain replication; for physical portability, use this ceremony.

---

## Part IV — Failure modes and their handling

**Card removed mid-write.** Substrate detects (filesystem sync failure or explicit ejection). Emits `chain:portable:export_incomplete` receipt naming the epoch and the partial write state. Retries at next epoch when card is remounted.

**Card corrupted or unmountable.** Substrate detects at mount time or write time. Emits `chain:portable:target_unavailable` receipt. Operator diagnoses (replace card, run filesystem check). Substrate does not silently degrade — the export target's availability is chain-anchored evidence.

**Card wrote successfully but later read shows corruption.** Portable verification (Phase P4) fails. Detected at operator-inspection time or during Phase P5 reconciliation. Operator can retry from any other portable export or from primary backup per `BACKUP-AND-RECOVERY-LANDSCAPE`.

**Operator Genesis rotated between exports.** Portable snapshots signed pre-rotation remain valid for what they attested (the epoch was signed by the operator-active-at-the-time). Post-rotation exports use new signing key. The `manifest.json` on any given card names ONE operator Genesis pubkey; if that changes, the operator either uses a new card for post-rotation exports OR updates the manifest with rotation-witness evidence (`genesis:rotated` receipt cited).

**Card cloned by adversary.** The portable medium is signed but not sealed. An adversary who obtains physical access to a portable card can copy it, but cannot modify its contents without invalidating the operator signature. Cloning produces multiple copies of the same signed content — trivially detectable at reconciliation time if they diverge (they can't, because they were byte-for-byte identical at clone time). If the concern is not "was it copied" but "does someone else have my chain content" — that's an operator physical-security problem, handled by keeping portable cards in operator-controlled physical locations.

**Card used for chain injection attack.** An adversary produces a card with forged content claiming to be operator chain. Defended by Phase P4's signature verification: content not signed by operator's Genesis-derived key fails validation. Chain-anchor imports emit `chain:portable:reconstitute_refused` if signature verification fails.

---

## Part V — Composition with existing specs

- **`BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md`** — portable snapshots are one of the backup surfaces named in the landscape. This spec elaborates the specific ceremony.
- **`REPRODUCIBILITY-CEREMONY-2026-07.md`** — peer verification can operate against a portable snapshot rather than requiring live-substrate access. Enables offline peer verification and "verify from a card" workflows.
- **`OPERATOR-DEATH-AND-LEGACY-2026-07.md`** — executor receives portable snapshots via pre-declared physical distribution (safe, safety-deposit box, kindred custody). Ceremony flow composes with legacy-access scope declarations.
- **`GENESIS-ROTATION-CEREMONY-2026-07.md`** — Part IV names the rotation-across-cards handling; the rotation ceremony's four phases compose with per-card manifest updates.
- **`MULTI-DEVICE-OPERATION-2026-07.md`** — portable export is orthogonal to fleet chain replication. Fleet replication for real-time redundancy; portable export for physical portability. Operators typically want both.
- **`SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md`** — aligned blindness at the source-chain level extends to the portable medium automatically.
- **`SOVEREIGN-HARDWARE-2026-07.md`** — portable cards are compatible with hardware kill switches. Some operators may want the export target to be physically switchable off (write-protect switch, physical removal); this ceremony composes with those hardware primitives.
- **`SUBSTRATE-BOOT-INVARIANT-CEREMONY-2026-07.md`** — the `portable_export_target` becomes a composition-matrix dependent surface. Adding a new sovereignty provider must verify portable export composes (per singular-sovereign-root discipline).
- **`SUBSTRATE-COORDINATION-DISCIPLINE-2026-07.md`** — portable export runs autonomously per operator-declared cadence, chain-anchored evidence; not a source of runaway alarms.

---

## Part VI — What this ceremony does NOT do

- **Real-time synchronization.** Portable snapshots are exported at epoch boundaries. Between epochs, the portable medium is out of date relative to live chain. Fleet chain replication (per MULTI-DEVICE-OPERATION) handles real-time.
- **Guarantee export freshness beyond last-exported epoch.** If the operator hasn't inserted the card recently, the last-exported epoch may be days or weeks old. This is by design — the ceremony is portable-media-optional.
- **Replace primary backup.** Primary backup discipline per BACKUP-AND-RECOVERY-LANDSCAPE remains the substrate's primary durability mechanism. Portable snapshots are additional; not a substitute.
- **Provide operator anonymity or plausible deniability.** The portable medium is signed and identifies the operator via Genesis pubkey embedded in the manifest. An adversary with physical access learns whose chain it is. Composes with physical-security operator discipline, not with structural anonymity claims.
- **Enable multi-writer operation to the same medium.** Only one substrate device writes to a given target at a time. Multiple devices writing to the same portable card is a coordination problem beyond this spec's scope.
- **Guarantee chain confidentiality at rest on portable medium.** The `.epoch` files contain the same content as on the source chain. If the source chain is unencrypted (typical), the portable medium is unencrypted too. For encrypted-at-rest portable snapshots, the operator composes this ceremony with ENCRYPTED-STORAGE-ARCHITECTURE-2026-07.md's derived-key encryption.

---

## Part VII — Verifiable outcomes

Testable claims that must hold post-implementation:

**Claim PE1:** for every epoch-anchored receipt on the source chain, if a portable target is declared and mounted at seal time, exactly one `chain:portable:exported` receipt is chain-anchored.

**Claim PE2:** the portable medium's `.epoch` file for epoch N contains the same content that hashes to the `epoch:anchored:N` receipt's Merkle root on the source chain.

**Claim PE3:** portable-side verification (Phase P4) succeeds if and only if the operator signature chain in `manifest.json` composes to a Genesis pubkey the verifier trusts AND every epoch's Merkle root recomputes correctly AND hash-link continuity holds.

**Claim PE4:** Phase P5 reconciliation from a portable medium produces the same chain state (up to the last exported epoch) as the original substrate at that epoch's completion time. Verifiable via cross-check: source chain state at epoch N == reconstituted chain state after importing up to epoch N.

**Claim PE5:** an adversary who modifies any byte of any `.epoch` file causes Phase P4 to fail. Structural, verifiable by direct test.

**Claim PE6:** Genesis rotation across export lifetime does not invalidate pre-rotation portable snapshots. Verifiable by rotating Genesis, then verifying a card exported pre-rotation still validates against the operator's rotation-history evidence.

**Claim PE7:** the ceremony composes with SUBSTRATE-BOOT-INVARIANT-CEREMONY's composition matrix — adding a new sovereignty provider (hypothetical YubiKey addition) forces re-verification of portable-export signing before merge.

---

## Part VIII — Follow-up work

**Immediate (implementation):**
- Extend `anchor_pipeline.rs` with the optional portable-export step.
- Add operator declaration flow via `zp chain export target set / remove / list` CLI verbs.
- Implement Phase P4 verifier as `zp chain export verify <card_path>`.
- Implement Phase P5 reconciliation flow.

**Near-term:**
- Compose with SUBSTRATE-COORDINATION-DISCIPLINE's cadence schedules for scheduled exports.
- Compose with SUBSTRATE-READINESS-CONTRACT's degradation receipts for target-unavailable states.
- Dashboard visualization of portable-target state (last exported epoch, staleness, target health).

**Longer-term:**
- Encrypted-at-rest portable snapshots for operators who want confidential portable media.
- Cross-substrate portable-import verification (peer confirms an imported snapshot matches their own view of the operator's chain, per REPRODUCIBILITY-CEREMONY).
- Portable-export bundle for executor / legacy access per OPERATOR-DEATH-AND-LEGACY.

**Deferred:**
- Multi-writer portable coordination (if fleet devices ever want to write to a shared card).
- Portable-snapshot merging (if operator wants to consolidate multiple cards into a single archive).

---

## Composes with / connects to

- **BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md** — portable snapshots as backup surface.
- **REPRODUCIBILITY-CEREMONY-2026-07.md** — offline peer verification.
- **OPERATOR-DEATH-AND-LEGACY-2026-07.md** — executor access via pre-declared card distribution.
- **GENESIS-ROTATION-CEREMONY-2026-07.md** — pre/post-rotation card handling.
- **MULTI-DEVICE-OPERATION-2026-07.md** — orthogonal to fleet chain replication.
- **SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md** — aligned blindness discipline extends to portable media.
- **SOVEREIGN-HARDWARE-2026-07.md** — kill-switch composition, write-protect support.
- **SUBSTRATE-BOOT-INVARIANT-CEREMONY-2026-07.md** — portable_export_target as composition-matrix dependent surface.
- **SUBSTRATE-COORDINATION-DISCIPLINE-2026-07.md** — autonomic coordination for scheduled exports; chain-anchored evidence, no runaway alarms.
- **SUBSTRATE-READINESS-CONTRACT-2026-07.md** — no_silent_degradation applies to portable-target-unavailable states.
- **ENCRYPTED-STORAGE-ARCHITECTURE-2026-07.md** — composes for encrypted-at-rest portable snapshots.
- **VAULT-KEY-SOVEREIGNTY-COMPOSITION-2026-07.md** — same singular-sovereign-root discipline applied to portable-export signing key derivation.

## CLAUDE.md workflow heuristics this exercises

- *Chain is truth; roll forward, never back.* — portable snapshots are the chain's physical projection at a specific epoch; reconciliation is import-forward, not rollback.
- *Signing is gravity.* — every export is operator-signed; unsigned portable content has no authority.
- *Store-and-forward is primary.* — the ceremony IS store-and-forward at the physical-medium layer.
- *Silence is the enemy, not compromise.* — target unavailability is chain-anchored, not silent.
- *Singular sovereign root: one authentication, everything derived.* — portable-export signing derives from Genesis alongside audit signing, vault key, media provenance signing.
- *Interoperability is composition, not conformity.* — portable format is operator-defined, verifiable independently, composable with any external tooling that respects operator Genesis.
