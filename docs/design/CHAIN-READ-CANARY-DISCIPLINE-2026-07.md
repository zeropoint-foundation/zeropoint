# Chain-Read Canary Discipline

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.2 (chain integrity discipline) and §III (adds Layer B canonical claims about read-path freshness verification). Companion to `OBSERVER-COHERENCE-DISCIPLINE-2026-07.md` (cross-observer verification). Canonical claims live in KEEL.

Draft — 2026-07-15 — internal audience only. Composes with `OBSERVER-COHERENCE-DISCIPLINE-2026-07.md` (bookend pair for observer fault detection), `CIRCUIT-BREAKER-2026-07.md` (sustained canary miss triggers escalation), `SUBSTRATE-COORDINATION-DISCIPLINE-2026-07.md` (KEEL III.25 — signal quality as coordination hygiene).

## Framing

Chain-anchored discipline works only if the substrate can *read* the chain accurately. Every officer, every Regent tool, every dashboard query, every Cognitive Input Plane composition depends on reading the current chain tail — not a fossilized snapshot from hours ago. When a read path returns stale data, every downstream decision inherits the staleness. Findings become confabulated, remediations act on outdated state, and the substrate silently reasons about a chain that no longer exists.

Discovered 2026-07-15 during P1.1 diagnosis. The server's shared rusqlite Connection was stuck at an 11-hour-stale read snapshot despite:
- WAL fully checkpointed (writes reached disk)
- Direct `sqlite3` CLI probe on same DB file showing fresh entries
- Single Connection, single Mutex, no obvious stuck Transaction or Statement in visible code

Steward's `check_chain_growth` reported "No chain entries in the last 658 minutes." Regent's `chain_query` on same connection saw entries from the last 30 minutes. Both read paths through the same `AuditStore`. One was stuck; nothing in the substrate flagged the discrepancy for hours. Only manual operator+external-agent diagnostic caught it, via cross-referencing with `sqlite3` CLI — an operation the substrate did not perform on itself.

Chain-read canary discipline is the substrate's structural response. Substrate periodically writes a canary marker entry to the chain, then immediately reads the chain tail through each declared observation path. If the canary is not visible in an observer's view, that observer's read path is stuck. Chain-anchored evidence of the drift emits; automatic connection rebuild fires; escalation triggers if the pattern recurs. The substrate detects its own observation-layer freshness fault within seconds, not hours.

Three properties frame the discipline:

1. **The canary is chain-anchored ground truth.** After the canary write commits, it *is* in the chain by definition (append-only + hash-linked). Any observer that doesn't see it is stuck, malfunctioning, or reading a different chain entirely — all faults.
2. **Verification runs per observer.** Every observer subsystem declared in the coherence class registry (per `OBSERVER-COHERENCE-DISCIPLINE-2026-07.md`) participates. Each has its own read path; canary probes each.
3. **Detection triggers structural remediation.** Missed canary is not merely a finding — it triggers automatic action: connection rebuild, statement cache flush, observer restart, or scoped circuit breaker. Chain-anchored evidence of the fault and the remediation.

## The canary receipt

Chain-anchored marker written at declared cadence:

```
{
  "event": "chain:canary:written:<canary_id>",
  "canary_id": "<sequential_id>",
  "issued_at": "<timestamp>",
  "issuer": "canary_runtime",
  "signature": "<runtime_signature>",
  "chain_link": {
    "prev_hash": "<...>",
    "index": <...>
  }
}
```

Small, cheap, structurally identical to other chain events. Distinguished only by the `chain:canary:written` action-event prefix so the verification probe can grep for it.

## The verification path

Immediately after the canary write commits, the canary runtime dispatches per-observer probes:

Per registered observer:
1. Invoke the observer's tail-read primitive (`recent_entries(N)`, `chain_query(limit=N)`, `search_by_keyword("chain:canary:written")`, etc.)
2. Check if `canary_id` from the just-written marker is present in the result
3. Record: observer identity, probe latency, canary present/absent

Probes are bounded (default 500ms per observer). Timeout counts as *unresponsive*, not *stuck*.

If canary present → observer is fresh. Emit `chain:canary:verified:<observer_id>:<canary_id>` receipt.

If canary absent (or non-timeout failure) → observer is stuck. Emit `chain:canary:missed:<observer_id>:<canary_id>` receipt with fields:
- Observer identity
- Canary ID that was expected
- What the observer's tail-read returned instead (summary hash of returned entries; not full contents)
- Probe latency
- Suggested remediation (typically: connection rebuild)

Missed canary is a *specific* finding class, not generic "observer error." It says: *this specific observer cannot see writes committed to the chain moments ago.*

## Automatic remediation

Missed-canary receipts trigger, per canonical Layer B remediation policy:

### Tier 1 — Statement cache flush

For observers backed by rusqlite: invoke `Connection::cache_flush()` or drop and re-prepare all cached statements. Cheap; often resolves stuck-statement issues.

Re-probe: emit second canary write and verify. If canary now visible → remediation succeeded, emit `chain:canary:remediated:<observer_id>:cache_flush`.

If still missed → escalate to Tier 2.

### Tier 2 — Connection rebuild

Drop and re-open the observer's Connection to the DB file. New Connection sees committed state fresh. Reconstruct any observer state that was cached on the old Connection.

Re-probe: verify. Emit `chain:canary:remediated:<observer_id>:connection_rebuild` on success.

If still missed → escalate to Tier 3.

### Tier 3 — Observer restart

Fully restart the observer subsystem (e.g., restart the sweep runner, reload the Cognitive Input Plane matrix). Requires the observer to be restart-safe (idempotent init).

Re-probe: verify. Emit `chain:canary:remediated:<observer_id>:observer_restart` on success.

If still missed → escalate to Tier 4.

### Tier 4 — Circuit breaker

Substrate-level fault. Chain read path is compromised at scope. Emit `chain:canary:critical:<observer_id>` and trip the circuit breaker per BLAST-RADIUS-AND-RECOVERY-2026-07.md. Observer marked untrusted; downstream decisions that would depend on this observer require operator co-sign or halt entirely. Operator ceremony required to reset.

## Cadence

Canary discipline runs at declared cadence per observer class. Rough defaults:

- Chain readers (Class 1 per coherence discipline): every 60 seconds. Highest cadence — chain-integrity dependence is broad.
- Ontology queriers (Class 2): every 5 minutes. Cartographer materialization is slower-changing.
- Observation-plane consumers (Class 3): every 60 seconds. Process/network state changes rapidly.
- Vault key listers (Class 4): every 5 minutes. Vault state changes on operator ceremony.

Cadence per class is Layer B canonical — operator ceremony to adjust.

## Cost bounds

Each canary probe costs: one chain write + N observer reads. Chain writes are cheap (sub-ms typically) but non-zero — canary discipline adds ~1 write per class per cadence interval.

Chain bloat over time: at 60-second cadence for chain readers, that's 1440 canary writes per day per class member. Small compared to normal chain activity but non-trivial over months. Auto-compaction routes them into archive along with other entries.

Chain compaction preserves canary receipts for post-hoc forensics. Historical canary-missed patterns are queryable for trend analysis — did observer X have a rough patch last Tuesday?

## Layer A / Layer B split

**Layer A (compiled Rust host):**
- Canary runtime — periodic dispatcher, canary write + verification pipeline
- Per-observer probe implementations
- Remediation dispatcher — Tier 1/2/3/4 escalation
- Signing infrastructure — Genesis-derived canary signing key
- Rate limiting and resource bounding

**Layer B (WASM modules + canonical data):**
- Observer registry (shared with coherence discipline)
- Per-observer tail-read primitive declaration
- Cadence per class
- Remediation policy per Tier
- Escalation thresholds (how many consecutive misses before circuit-breaker trip)

Layer A structurally defended; Layer B evolves via canonicalization ceremony.

## Provenance — canary signing key

Per KEEL §II.5: single signing key, HKDF-derived from Genesis:

```
canary_key = HKDF(genesis_root, salt=chain_head_at_derivation, info="canary:runtime")
```

Signs `chain:canary:*` receipts. Attribution to Genesis via one hop.

## Composition with Substrate Form

Canary discipline available on all Forms with observer set varying:

### Sovereign Form

Full observer set. All coherence classes populated with canary probes. All remediation tiers available (Sovereign-Form has authority to restart subsystems within substrate).

### Appliance Form

Same as Sovereign on the appliance. Cross-Appliance-to-daily-driver canary not attempted (different substrates, different chains).

### Companion Form

Observation-plane observer set reduced (per SUBSTRATE-FORM-2026-07.md vendor-limited reach). Class 1, 2, 4 canary discipline unchanged. Class 3 canary probes only the observers actually available.

## Composition with observer coherence discipline

Bookend pair for observer fault detection (from OBSERVER-COHERENCE-DISCIPLINE-2026-07.md §"Composition with the chain-read canary discipline"):

- **Canary discipline** (this spec) — single-observer freshness: does observer X see the canary marker after it was written?
- **Coherence discipline** — cross-observer agreement: do observers X and Y report the same underlying data?

Combined behavior:
- Canary fresh + coherence agree → all observers healthy
- Canary fresh + coherence diverge → observers read different data even though they're all seeing the latest — misconfigured filter, wrong query, buggy read logic
- Canary stale for one observer + coherence would have caught the divergence anyway → canary catches it faster (single-observer probe) than coherence (cross-observer compare)
- Canary stale for all observers → substrate's write path may be broken, not just read path; higher-order fault

The two disciplines share the observer registry (Layer B) and reinforce each other.

## Composition with the Circuit Breaker

Per canary-remediation tier ladder above. Additionally, sustained canary-missed patterns across multiple observers trigger substrate-level escalation:

- **L1 — Elevated attention**: single observer misses one canary → auto-remediate at Tier 1
- **L2 — Rate limit**: same observer misses N canaries in M minutes despite remediations → downgrade observer trust, require corroboration for its findings
- **L3 — Soft arrest**: multiple observers missing canaries → chain read path partially compromised; Regent's actions requiring chain-read grounding require operator co-sign
- **L4 — Hard trip**: canary discipline itself failing (own probes not writing or not returning) → substrate posture set to `observation_layer_untrusted`; operator ceremony required to reset

## Attack model

- **Attacker suppresses canary writes to hide observer staleness**: canary writer is a Layer A subsystem with its own signing key; disabling requires substrate compromise; runtime heartbeat monitored; sustained absence triggers L4 escalation.
- **Attacker seeds fake canary receipts in observer views**: canary_ids are runtime-signed with sequential IDs; substrate verifies signature and sequence.
- **Attacker forces observer read path to always return the freshest canary while returning stale data for everything else**: covered by coherence discipline — even if canary check passes, cross-observer disagreement on real data catches it.
- **Attacker floods with canary-missed findings to fatigue operator**: canary runtime's own resource bounds prevent runaway emission; L4 trip requires sustained multi-observer pattern.
- **Attacker corrupts remediation to make faults appear resolved**: remediation receipts are chain-anchored; operator can query for a specific observer's remediation history and cross-reference with subsequent canary-verification receipts.

## Non-goals

- **Not for external chains.** Canary discipline verifies substrate-internal read paths. Peer-substrate chain reads have their own verification per peer-verification contract.
- **Not for content correctness.** Canary verifies *freshness* — was the just-written entry visible? Content verification is Cognitive Self-Observer's job (verifies Regent's semantic claims against ground truth).
- **Not a replacement for observer coherence.** Canary is single-observer freshness; coherence is cross-observer agreement. Different failure modes; complementary.
- **Not zero-cost.** Every cadence adds one chain write per class per interval. Trivial per-write but non-zero at scale.
- **Not real-time gating.** Canary probes are asynchronous; they don't block observer reads inflight. Blocking behavior belongs to Claim Verifier for capability claims.

## Open positions

- **Cadence tuning.** 60-second default for chain readers may be too aggressive; empirical calibration.
- **Canary chain-bloat management.** Auto-compaction handles them but archive grows. Consider dedicated canary retention policy — keep last N per observer, archive older.
- **Cross-Form canary.** Do canaries emitted on Sovereign propagate to Appliance/Companion via peer-verification contract? Deferred until peer-verification implementation matures.
- **Regent-invoked canary.** Should Regent be able to trigger an on-demand canary probe as a diagnostic tool? Yes, low-risk; adds `canary_probe` tool. Composes with Regent's `act on precedent, escalate on novelty` heuristic.
- **Remediation authorization.** Tier 1 (statement cache flush) is trivially safe. Tier 2 (connection rebuild) affects the substrate's I/O state — could interrupt in-flight writes. Requires careful sequencing. Tier 3 (observer restart) requires idempotent init. Tier 4 (circuit trip) requires operator ceremony to reset.
- **Multi-observer batched probes.** For same-class observers, one canary write can verify all members' visibility. Bundle rather than probe-per-observer? Reduces chain-write cost.

## What composes from here

Immediate design work:

1. Canary receipt schema (Layer B canonical)
2. Per-observer tail-read primitive declaration (shared with coherence discipline observer registry)
3. Remediation tier policy schema
4. Finding schema for `chain:canary:*` receipts (written / verified / missed / remediated / critical)
5. Cadence config per observer class
6. Dashboard panel: "Canary discipline" view with per-observer freshness history

Near-term implementation:

1. Canary runtime Layer A in `crates/zp-server/src/canary/`
2. Per-observer probe implementations (start with Class 1 chain readers — highest-value, immediately fixes the P1.1 fault)
3. Remediation tier 1 (statement cache flush) — simplest, covers many stuck-connection cases
4. Feedback loop integration — findings flow to Cognitive Input Plane's Tier 2 (substrate state snapshot)
5. Circuit breaker integration — sustained multi-observer canary loss escalates
6. Composition with coherence discipline for combined observer-fault detection

## Framing note

Chain-anchored discipline was the substrate's founding principle. Every action produces a signed receipt; the chain is the source of truth; every trust decision derives from the chain. But the whole architecture rests on the substrate being able to *read the chain accurately*. When a read path silently goes stale, the substrate keeps operating on a fossilized chain, and every downstream discipline inherits the corruption.

The 2026-07-15 P1.1 diagnostic session exposed this specific gap. The substrate had officers watching chain integrity, cognitive observers watching Regent's outputs, and a Cognitive Input Plane composing chain state into Regent's context — but no discipline to verify that any of them could actually read the current chain tip. The bug hid in plain sight for hours because the substrate had no structural mechanism to detect it.

Combined with observer coherence discipline (OBSERVER-COHERENCE-DISCIPLINE-2026-07.md), chain-read canary closes the observation-layer trust envelope. Every observer subsystem has both a freshness check (canary) and a cross-observer verification (coherence). Faults in either dimension become chain-anchored findings within seconds, trigger structural remediation, and escalate through the circuit breaker if persistent. The substrate can *read its own chain reliably* — not because reads happen to work, but because the substrate structurally verifies that they do.

The load-bearing philosophical claim: chain integrity is not a property of the chain alone; it is a property of the whole read/write loop. A chain with perfect writes but broken reads is functionally equivalent to a corrupted chain — every downstream consumer sees corruption. Read-path fidelity is engineered, not hoped for. Canary discipline is how the substrate proves, structurally and continuously, that its own view of its own chain is fresh.
