# Substrate Exit Ceremony

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), §III.20 (forward-only recovery), §III.23 (coordination not oversight), Part VII (Peer-Verification Contract), Part VIII (bounded operator sovereignty). Specifies the ceremony for an operator who chooses to leave the substrate entirely while alive — distinct from operator death, distinct from substrate migration to new hardware. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `OPERATOR-DEATH-AND-LEGACY-2026-07.md` (structurally related — both are forward-authority-terminating; exit is voluntary and operator-driven), `SUBSTRATE-MIGRATION-CEREMONY-2026-07.md` (exit is not migration to another substrate; operator is leaving substrate entirely), `SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md` (kinship notifications on exit), `PEER-TRUST-ANCHOR-2026-07.md` (peer trust anchor updates), `HOUSEHOLD-COMPOSITION-2026-07.md` (household member departure).

## Framing

Some operators will choose to leave the substrate entirely. Reasons vary: personal choice ("this isn't for me anymore"), circumstance change (moving to a life context where substrate infrastructure doesn't fit), values reconsideration ("I don't want this level of chain-anchoring in my life"), aging into simpler technology preferences, or just changing minds. This is legitimate operator choice. The substrate must handle it gracefully.

Exit is distinct from three adjacent concepts:

- **Not death.** Operator is alive and choosing this transition themselves. No executor needed. Operator retains authority throughout the ceremony.
- **Not migration.** Operator is not moving substrate to new hardware; they are ending their substrate operation entirely. Chain does not travel to a new substrate; it either preserves in place, archives, or (under specific ceremonies) deletes.
- **Not dormancy.** Operator is not pausing substrate use for extended offline period; they are permanently leaving. Return requires re-onboarding as new sovereign (with new Genesis) or specific re-entry ceremony.

Three properties frame the ceremony:

1. **Operator authorizes every step.** Exit is voluntary; operator remains authoritative throughout. Chain preservation choices are operator's; kinship notification preferences are operator's; hardware disposition is operator's. Substrate does not resist exit but requires operator ceremony for each transition.
2. **Chain handling is operator-chosen from bounded options.** Chain is truth; deletion is a serious choice. Operator can preserve chain (personal archive, family archive, community archive), archive with legacy access (per OPERATOR-DEATH-AND-LEGACY legacy scopes but applied to voluntary exit), or delete (with sovereignty implications spelled out).
3. **Peer and kinship notifications are chain-anchored.** Federated peers and kindred sovereigns need to know. Notifications flow with content per operator's preferences; peers update trust anchors; kindred sovereigns' Regents adjust accordingly.

## The three chain handling options

Central operator decision: what happens to the chain.

### Option A — Preserve in personal archive

Chain content preserved at operator-controlled destination outside active substrate operation. Common destinations:

- Operator-controlled personal archive (encrypted local storage; personal backup medium)
- Family archive (chain moves to family member's substrate for retention)
- Third-party archival service under operator agreement

Chain remains cryptographically intact; chain is no longer connected to peer-verification network. Operator can access their own historical record; chain-anchored evidence of past actions persists.

Emit `exit:chain_preserved:<destination_class>` receipt. Chain archive destination attested.

### Option B — Preserve with community/federation archive

Chain archived by community or federation archival service per operator declaration. Similar to posthumous archival per OPERATOR-DEATH-AND-LEGACY but voluntary. Legacy scope declarations can activate (specific chain content accessible to designated beneficiaries per operator's declared scopes).

Emit `exit:chain_archived_community:<archive_id>` receipt.

### Option C — Delete

Chain content deleted from operator's substrate. Sovereignty implications:

- Operator's Genesis retires; forward authority ends
- Chain-anchored evidence of past actions is deleted (from operator's copy; peer replicas per Peer-Verification Contract may still exist)
- Historical continuity of operator's sovereign identity ends
- Future re-entry requires new Genesis (new sovereign identity); prior kinships and relationships are severed from any future sovereignty operator establishes

Deletion is significant. Substrate surfaces implications clearly before ceremony. Operator can proceed but with full understanding.

Emit `exit:chain_deleted:<confirmation_id>` receipt on operator's substrate before deletion. Peer replicas receive `exit:chain_deleted:notification:<sovereign_id>` receipts; peers may retain their own copies of receipts operator sent to them (chain content operator sent to peers is peer's chain evidence, not operator's, per Peer-Verification Contract).

Some jurisdictions may have data retention requirements that constrain deletion; substrate does not automatically comply with jurisdiction-specific regulation — operator responsibility.

## Ceremony phases

### Phase 1 — Exit declaration

Operator emits `exit:initiated:<exit_id>` receipt with:
- Exit reason (optional; operator-declared or omitted)
- Chosen chain handling (Options A/B/C)
- Timing (immediate, scheduled)
- Kinship notification preferences
- Peer notification preferences
- Hardware disposition preferences

Signed by operator's Genesis. Ceremony begins.

### Phase 2 — Kinship notifications

Kindred sovereigns notified per operator's preferences. Notification content is bounded:

- Kindred receive `sovereign:exit_declared:<sovereign_id>` receipts
- Kindred's Regents surface to their operators per their own preferences
- Kindred can respond via their own channels (human contact, farewell messages, etc.)

Cross-Regent narrations for exit are strictly scope-compliant. Care sovereigns may receive earlier notification per operator preference.

Household members (per HOUSEHOLD-COMPOSITION) receive household-scope notification; household composition ceremony updates member composition.

### Phase 3 — Extension conclusion

Extensions running on operator's substrate conclude:

- Extensions with peer-facing state receive graceful shutdown signals
- Extension state preserved per extension's own retention policy or discarded per operator preference
- Emit `extension:concluded:<extension_id>:<reason>` receipts

### Phase 4 — Peer notification

Federated peers notified via peer distribution. Peers update trust anchors for the exiting operator:

- Operator's Genesis retires from active operations
- Historical peer-verified signatures remain valid as historical evidence
- Forward peer verifications from this operator will not occur

Peers emit `peer:sovereign_exited_acknowledged:<sovereign_id>:<exit_id>` receipts on their chains.

### Phase 5 — Chain handling execution

Per operator's chosen chain handling option (A/B/C), chain content is preserved, archived, or deleted.

For preservation: chain content transferred to destination with cryptographic integrity verification. Destination attested.

For archival: chain content transferred to community/federation archival service. Legacy scopes if declared become active.

For deletion: chain content deleted after peer notification propagation; operator receives confirmation of deletion completion.

### Phase 6 — Regent conclusion

Regent transitions from serving-operator to exit state:

- No new dispatches accepted
- Existing cognitive state preserved briefly for exit ceremony narration, then either archived (per chain handling choice) or discarded

Emit `regent:exit_state:<sovereign_id>` receipt.

### Phase 7 — Hardware disposition

Operator directs hardware disposition per their preference:

- Retain hardware for other uses (wiped of substrate state per chain handling choice)
- Gift hardware (wiped)
- Recycle hardware (wiped)
- Destroy hardware (physical destruction)

Emit `exit:hardware_disposition:<disposition_type>:<disposition_id>` receipt.

### Phase 8 — Genesis retirement

Operator's Genesis material handled per operator preference:

- **Retained** in operator's custody for personal significance (hardware token as memorial to their sovereignty era)
- **Destroyed** to prevent any future forgery attempts (physical destruction of hardware token)
- **Transferred to trusted family** for potential legacy use per operator declaration

In all cases, Genesis is not used for forward signing after exit ceremony. Emit `exit:genesis_retired:<retention_class>` receipt.

### Phase 9 — Exit completion

Substrate emits final `exit:completed:<exit_id>` receipt. Substrate ceases operations. Operator has left.

## Re-entry considerations

Operator who exits and later wishes to return:

### Re-entry as new sovereign

Establish new Genesis, new chain, new sovereign identity. All prior relationships are re-established from scratch as human-authored acts:

- New kinships must be freshly declared (prior kinships were severed at exit)
- Peer trust anchors are established fresh
- Household memberships are re-negotiated
- No continuity of prior sovereign identity — new identity, new life

This is the primary re-entry path. Operator making this choice does so with full understanding that prior sovereignty is not being restored.

### Re-entry via chain restoration (if preserved)

If exit chose Option A or B (chain preserved), operator can potentially restore their previous sovereign identity by:

1. Retrieving preserved chain from archive
2. Re-establishing Genesis authority (composes with GENESIS-ROTATION-CEREMONY)
3. Re-establishing peer trust anchors (peers re-verify)
4. Kinship re-establishment (kindred sovereigns may or may not choose to re-establish kinship; substrate doesn't force)

Restoration is more complex than fresh sovereign onboarding but preserves continuity. Not always successful (peer trust anchor rebuilding requires peers' consent; kindred may have moved on).

## Composition with existing specs

- **OPERATOR-DEATH-AND-LEGACY**: structurally similar but operator-driven vs executor-driven. Some infrastructure (legacy scopes, archival mechanisms) shared. Exit is voluntary; death is not.
- **SUBSTRATE-MIGRATION-CEREMONY**: exit is not migration. Migration moves substrate to new hardware while preserving operator sovereignty. Exit ends operator sovereignty on substrate.
- **SOVEREIGN-KINSHIP-PRIMITIVES**: kinship notifications on exit; kinships end (unless re-entry restores).
- **PEER-TRUST-ANCHOR**: peers update trust anchors on exit notification.
- **HOUSEHOLD-COMPOSITION**: household member departure via household-specific ceremony coincides with exit.
- **DEPENDENT-SOVEREIGNTY**: if exiting operator is guardian for dependent sovereign, guardianship succession per DEPENDENT-SOVEREIGNTY (guardian scopes transfer to other guardians per operator's declaration or family/community ceremony).

## Attack model

- **Attacker forges exit declaration to sever operator's substrate**: exit requires operator's Genesis signature. Forgery requires Genesis compromise, handled by Genesis rotation ceremony.
- **Attacker exploits partial exit state (mid-ceremony) to attack**: ceremony state chain-anchored per phase; substrate does not accept new operations from midpoint-exited operator; peers respect the chain-visible exit progression.
- **Attacker manipulates chain-deletion to erase evidence of their own past actions**: attacker's actions are attacker's chain-visible receipts; deleting operator's chain doesn't delete attacker's own chain records if attacker has their own substrate. Peers may retain evidence of operator's outbound actions per Peer-Verification Contract.
- **Attacker exploits legacy scope activation during voluntary exit**: legacy scopes require operator's pre-declaration (via ceremony similar to OPERATOR-DEATH-AND-LEGACY). Attacker cannot inject legacy scopes without operator's Genesis.
- **Attacker uses hardware disposition ceremony to gain access to substrate hardware**: hardware disposition is operator's ceremony; operator directs physical handling.

## Failure modes

- **Peers do not acknowledge exit within reasonable window**: peers may be offline; exit ceremony completes on operator's side; unacknowledged peers eventually observe exit via chain replication.
- **Chain preservation destination fails**: preservation ceremony includes verification of destination readiness; failure aborts exit at chain handling phase; operator can choose different destination.
- **Kindred sovereign objects to exit notification content**: notification content is bounded per kinship scope; kindred can respond via human channels; substrate does not require kindred consent for operator's exit.
- **Household is left with only one member**: household member departure creates degenerate single-member household; per HOUSEHOLD-COMPOSITION, either dormant or candidate for dissolution.
- **Chain deletion fails partially**: per-shard deletion verification; failure receipt lists shards deleted vs remaining; operator can retry.
- **Regret post-exit**: if chain was preserved (Options A/B), re-entry restoration is possible. If chain was deleted (Option C), only new sovereign onboarding is available.

## Non-goals

- **Not automatic exit under any circumstances**. Exit is voluntary operator ceremony; substrate does not autonomously exit operator (not under circuit breaker, not under peer consensus, not under any external trigger).
- **Not chain deletion for third-party privacy claims**. Substrate does not delete chain content in response to external requests; operator is authoritative over their own chain.
- **Not migration to non-substrate systems**. Exit ends substrate participation; operator's data in external systems is external systems' concern.
- **Not universal peer replica deletion**. Peer replicas per Peer-Verification Contract are peers' chain content; operator's exit does not compel peers to delete their own chain records.
- **Not restoration guarantee for chain-preserved exits**. Restoration is possible but requires peer trust anchor rebuilding, which peers may or may not consent to.
- **Not enforcement of exit finality**. Operator can change mind post-declaration up to ceremony completion; substrate honors operator's authority throughout.

## Open positions

- **Exit UX**: how does substrate surface exit option to operators? Dashboard flow? CLI verb? Deliberately not-easy-to-find (to prevent accidental exits) vs discoverable (to respect operator autonomy)?
- **Chain deletion granularity**: full chain deletion vs selective (delete specific receipt classes)? Trade-off: operator flexibility vs cryptographic integrity of partial chains.
- **Peer replica cleanup**: operator can request peers to delete their copies of receipts operator sent; peers may or may not comply. Federation working spec.
- **Exit cooldown period**: should exit ceremony have delayed completion (e.g., 30 days before final chain handling)? Prevents impulsive exits but complicates decisive exits.
- **Re-entry restoration UX**: restoring previously-preserved chain vs starting fresh; helping operator understand the trade-offs.
- **Community exit ceremonies**: some operators may want community-witnessed exit ceremonies (goodbye messages, community farewell). Chain-anchored optional.
- **Partial exit (retain sovereignty but reduce substrate activity)**: is there a "lite" mode between full exit and full operation? Or is this served by existing operator preferences?
- **Cross-jurisdiction exit compliance**: jurisdictions with data retention or export requirements may constrain deletion choices; operator responsibility.

## What composes from here

Immediate design work:

1. **Exit ceremony phase receipts** — schema per phase
2. **Chain handling option schemas** — preservation, archival, deletion protocols
3. **Kinship notification protocol on exit** — content boundaries per scope
4. **Peer notification distribution** — how exit propagates through federation
5. **Re-entry restoration protocol** — chain retrieval + peer trust anchor rebuilding

Near-term implementation:

1. Exit ceremony coordinator in `crates/zp-server/src/exit/`
2. Chain handling executors per option
3. Extension conclusion protocol
4. Peer notification protocol
5. Genesis retirement handling
6. Dashboard: exit ceremony panel (with strong deliberation UX to prevent accidents)
7. CLI verbs: `zp exit initiate|status|complete`

## Framing note

Substrate exit ceremony addresses the operator's legitimate choice to leave. Same principle as chain-anchored discipline elsewhere — operator authorization for consequential state changes, chain records what happens, ceremony marks transitions.

The load-bearing insight: **operators are free to leave the substrate.** Substrate is chosen infrastructure, not imposed one. Operator who chooses exit is authoritative over the ceremony; substrate handles gracefully; chain preserves ceremony as historical record. Neither substrate nor peers nor kindred sovereigns can prevent legitimate exit. Exit reserves the operator's right to change their mind about substrate participation without erasing their sovereignty over their own choices.

Combined with the substrate's structural discipline across every trust boundary, exit ceremony completes the voluntary-transition envelope. What was previously implicit — someone stops using their infrastructure; digital residue accumulates ad-hoc — becomes structural: ceremony declaration, kinship notifications, extension conclusions, peer notifications, chain handling per operator choice, hardware disposition, Genesis retirement. Sovereignty is preserved because operator authorizes throughout; safety is preserved because ceremony is chain-anchored evidence; freedom is preserved because operator's choice to leave is honored fully.
