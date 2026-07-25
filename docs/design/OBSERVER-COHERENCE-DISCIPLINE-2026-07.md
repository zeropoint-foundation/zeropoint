# Observer Coherence Discipline

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §III (adds Layer B canonical claims about cross-observer verification of shared substrate state) and Part V (Composition Contract for observer subsystems). Companion to `COGNITIVE-SELF-OBSERVER-2026-07.md` (which observes Regent's outputs against ground truth) and `SHADOW-EVALUATION-PRIMITIVE-2026-07.md` (which compares candidate vs control policy surfaces). Canonical claims live in KEEL.

Draft — 2026-07-15 — internal audience only. Composes with `CHAIN-READ-CANARY-DISCIPLINE-2026-07.md` (single-observer staleness detection), `OBSERVATION-PLANE-2026-07.md` (source of observation-plane observers), `CIRCUIT-BREAKER-2026-07.md` (sustained coherence loss triggers escalation), `SUBSTRATE-COORDINATION-DISCIPLINE-2026-07.md` (KEEL III.25 — signal quality as coordination hygiene).

## Framing

When multiple substrate components observe the same underlying state, they should produce coherent views. Steward's chain integrity check and Regent's `chain_query` tool both read `audit_entries`. Cleo's delegation view and Sentinel's chain-based finding look at the same receipts. Two officers scanning process state through the observation plane should see the same processes. If any of these agree on the underlying data but disagree on what they see, one of the observers is broken — or the substrate's connection to ground truth is broken — and that fact is *a first-class signal* the substrate should catch itself.

Discovered structurally 2026-07-15 during P1.1 diagnosis. Steward's `check_chain_growth` reported "No chain entries in the last 658 minutes." Regent's `chain_query` on the same substrate at the same moment saw entries throughout the last 30 minutes. Direct `sqlite3` CLI probe on the same DB file confirmed Regent's view was correct — chain was actively writing. Two observers of the same underlying state disagreed by 11 hours. The divergence was the smoking gun that identified a stuck-connection bug. But the substrate had no explicit discipline to catch that divergence — it took an operator+external-agent diagnostic session to notice.

Observer coherence discipline is the substrate's structural response. Substrate periodically dispatches cross-checks that pair observers of the same underlying state, compare their outputs via canonical hash / summary metrics, and emit chain-anchored discrepancy findings when they disagree beyond tolerated variance. The finding IS the diagnosis — it names which observers diverged, what they claimed, and against what ground truth. Investigation and remediation follow the standard officer→operator ceremony pattern.

Three properties frame the discipline:

1. **Coherence is a substrate invariant.** Two observers with the same declared source that produce different views cannot both be correct. The substrate treats this as a fact-of-substrate, not a matter of opinion — the ontology has a truth to it, and if observers see different truths, at least one is malfunctioning.
2. **Detection is periodic and chain-anchored.** Cross-checks fire at declared cadence, the pairings run, and results emit chain-anchored discrepancy or agreement receipts. Every cross-check produces evidence — regular agreement is quiet posture; divergence is loud finding.
3. **Findings are diagnostic, not judgmental.** Coherence divergence names *who disagreed* and *what they said*; it does not name *who's right*. Ground truth arbitration is subsequent work — typically resolved via direct-source probe (per canary discipline) or operator ceremony.

## Coherence classes

Not all observers observe the same thing. The discipline groups observers into *coherence classes* — sets of observers that legitimately should agree because they share a declared source.

### Class 1 — Chain readers

Multiple substrate paths read the same `audit_entries` table. All should see the same chain tip.

Members (as of 2026-07-15):
- Steward's `check_chain_growth` via `ChainReader::recent_entries`
- Steward's `check_chain_integrity` via `ChainReader::verify` → `verify_with_report` → `export_chain`
- Cleo's delegation walk via `ChainReader::search_by_keyword`
- Sentinel's finding queries via `ChainReader::search_by_keyword`
- Regent's `chain_query` tool via `AuditStore::recent_entries` / `search_chain_by_action_keyword`
- Cognitive Input Plane's standing correction reader via `search_chain_by_action_keyword`
- Cognitive Self-Observer's precedent lookup via `search_chain_by_action_keyword`

Coherence probe: fetch chain-tail summary (max rowid + hash + timestamp) via each member; hashes should match. Divergence emits `coherence:diverged:class1_chain_readers` receipt naming the members and their disagreement.

### Class 2 — Ontology queriers

Multiple substrate paths query the Cartographer-materialized ontology. All should see the same object graph.

Members: Regent (via ontology tools), officer queries against ontology-indexed views, dashboard rendering paths.

Coherence probe: fetch object-count summary + last-canonicalization hash per member; disagreement flags either stale Cartographer materialization or corrupted read path.

### Class 3 — Observation-plane consumers

Multiple substrate paths consume the observation plane's state. All should see the same substrate footprint for each surface family they share. Class 3 generalizes across every observation-plane surface (per `OBSERVATION-PLANE-2026-07.md` §The eight observation surfaces); the probe is surface-parameterized.

**Members and coherence sub-classes**:

- **3a — Process/network state**: Steward (host-state check), Sentinel (unauthorized listener detection), Forge (tool lifecycle awareness), Regent (system_status), dashboard (topology view). Probe: `hash(sorted_listener_pids ⊕ hash(sorted_process_names))`.
- **3b — Filesystem posture**: Steward (volume/log hygiene), Forge (log growth), Regent (via substrate state snapshot). Probe: `hash(sorted_volume_ids ⊕ per_volume_usage_bucket)`.
- **3c — Display topology**: dashboard (staging surface), Regent (via cognitive input plane), embodiment behavior controller (placement resolver). Probe: `hash(sorted_display_ids ⊕ topology_arrangement_hash)`.
- **3d — Operator face signals**: Regent's cognition (via cognitive input plane Class 7), embodiment behavior controller, Cleo (narration), dashboard (observation-active indicator), presence-driven policy responders. Probe: `hash(latest_face_observation_per_authorized_signal)` — one hash per active signal delegation, compared across consumers reading that same signal.

For each surface family, disagreement flags observation-plane routing bug, scope-delegation misalignment for that consumer, or stale materialization at one consumer's read path. Cross-surface comparison (Steward's chain view against dashboard's display topology, say) is a Class 3 non-member — legitimately different underlying state.

The Layer B canonical spec maintains a per-surface consumer registry; adding a new observation surface (per OBSERVATION-PLANE canonicalization ceremony) adds a new Class 3 sub-class with its own probe specification.

### Class 4 — Vault key listers

Multiple substrate paths enumerate vault key names (never values — per aligned blindness KEEL III.24). All should see the same key set.

Members: Steward's `check_vault_hygiene`, Sentinel's `shadow_credential` detection, Cleo's delegation-consistency checks, Regent's memory queries.

Coherence probe: fetch key-name-set hash per member; disagreement flags vault-load path bug.

### Additional classes emerge as substrate grows

Each new observer added to the substrate declares which coherence class it belongs to. The Layer B canonical spec maintains the class → member registry.

## The cross-check runtime

Layer A component that periodically pairs observers within each class and compares their outputs.

### Trigger

The coherence runtime fires at declared cadence (default: every 5 minutes for each class; configurable). Can also fire on demand via operator or Regent request. Also fires immediately when a canary miss (per `CHAIN-READ-CANARY-DISCIPLINE`) suggests a specific observer may be stale — cross-check confirms which observers are affected.

### Coherence probe per class

Per class, run each member's probe query. Collect the summary results. Compute pairwise agreement:

- Class 1: fetch `(max_rowid, tail_entry_hash, tail_timestamp)` via each member. Compare all pairs.
- Class 2: fetch `(object_count, canonicalization_hash)` per member. Compare all pairs.
- Class 3: fetch `hash(sorted_listener_pids ⊕ hash(sorted_process_names))` per member. Compare all pairs.
- Class 4: fetch `hash(sorted_key_names)` per member. Compare all pairs.

Probes are bounded (default 500ms per member; configurable). If a probe times out, the member is marked *unresponsive*, not *divergent* — different finding class.

### Comparison

For each pair within a class:
- **Exact match**: no finding
- **Match within tolerated variance**: some classes accept minor drift (e.g., Class 3 process observation may see a listener that started/stopped between probes; tolerated if within 500ms window). Configurable per class.
- **Divergence**: emit `coherence:diverged:<class>:<probe_id>` receipt with:
  - Which members were paired
  - Each member's returned summary
  - Ground-truth probe result if available (see next section)
  - Divergence magnitude (in class-specific units)
  - Severity per magnitude and class

### Ground-truth arbitration (optional)

When a divergence fires, the runtime can optionally invoke a *ground-truth probe* — a canonical read that bypasses the observer layer and hits the source directly. For Class 1, that's a direct `sqlite3` read of the tail (via a separate connection). For Class 3, a direct syscall bypass. For Class 4, a raw vault decrypt-and-enumerate (still no values — just names).

Ground-truth probes are expensive and require operator authorization for scope. Not run on every divergence — only when the runtime is configured to arbitrate rather than merely observe. Default: observe only; arbitrate on operator request.

When arbitrated, the divergence finding names *which observer's view matched ground truth* and *which observers were stale*. Investigation targets the stale observers.

### Report

The coherence runtime emits, per probe cycle:

- **On clean sweep**: `coherence:verified:<class>` — evidence that class members agreed. Low-severity, chain-anchored posture.
- **On divergence**: `coherence:diverged:<class>:<probe_id>` — high-severity finding per §"Comparison" above.
- **On ground-truth arbitration**: `coherence:arbitrated:<class>:<probe_id>` — names truth-matching and stale members.

Findings feed the Cognitive Input Plane at Tier 2 (substrate state snapshot) — Regent perceives coherence state alongside chain state and officer findings. Regent can query her own chain for coherence patterns via chain_query.

## Layer A / Layer B split

**Layer A (compiled Rust host):**
- Coherence runtime — periodic cross-check dispatcher
- Per-class probe implementations
- Comparison and finding emission
- Signing infrastructure — Genesis-derived coherence signing key
- Ground-truth arbitration probes (per class, gated by operator delegation)
- Rate limiting and resource bounding

**Layer B (WASM modules + canonical data):**
- Coherence class registry — members per class
- Probe specifications per class (what to fetch, how to hash, tolerance)
- Comparison threshold config
- Ground-truth arbitration policy (when to arbitrate, scope authorization)
- Class → cadence config

Layer A structurally defended; Layer B evolves via canonicalization ceremony. Adding a new observer to a class — Layer B ceremony. Changing tolerance thresholds — Layer B ceremony.

## Provenance — coherence signing key

Per KEEL §II.5: single signing key, HKDF-derived from Genesis:

```
coherence_key = HKDF(genesis_root, salt=chain_head_at_derivation, info="coherence:runtime")
```

Signs `coherence:*` receipts. Attribution to Genesis via one hop.

## Composition with Substrate Form

Coherence discipline available on all Forms with member set varying:

### Sovereign Form

Full class membership. All coherence classes populated. Ground-truth arbitration authorized (operator holds all scopes).

### Appliance Form

Same as Sovereign on the appliance. Some Class 3 observation-plane members bounded to appliance perimeter; daily-driver observation not cross-checked with appliance-side observation (different substrates, different observers, different classes).

### Companion Form

Class 3 observation-plane membership reduced (vendor-limited observation reach per SUBSTRATE-FORM-2026-07). Form Disclosure names the reduction. Class 1, 2, 4 remain fully populated.

## Composition with the chain-read canary discipline

Bookend pair for observer fault detection:

- **Canary discipline** (CHAIN-READ-CANARY-DISCIPLINE-2026-07.md) — single-observer freshness: does observer X see the canary marker after it was written?
- **Coherence discipline** (this spec) — cross-observer agreement: do observers X and Y report the same underlying data?

Canary catches freshness bugs (observer stuck at old snapshot); coherence catches structural read-path bugs (observer reads wrong data even when fresh). A single-connection stall would be caught by both. A per-connection read-filter misconfiguration would be caught by coherence alone. A network partition to a remote observer would be caught by canary alone.

Together they close observer-fault detection: if canary is fresh AND coherence agrees, all observers are healthy. Any other combination is a specific fault class with specific remediation.

## Composition with Cognitive Self-Observer

CSO verifies Regent's *outputs* against ground truth. Coherence verifies *observers* against each other. Related but different: CSO catches Regent's semantic mistakes; coherence catches substrate observation-layer mistakes underneath cognition.

Regent's `chain_query` output being correct (via CSO verification) doesn't guarantee Steward's `chain_growth` is also correct. The 2026-07-15 diagnostic showed this exactly: Regent's chain_query was correct; Steward's read was 11 hours stale. CSO alone wouldn't catch Steward's silence. Coherence discipline would.

## Composition with the Circuit Breaker

Sustained coherence divergence at scope triggers circuit breaker escalation per BLAST-RADIUS-AND-RECOVERY-2026-07.md §"Escalation Ladder":

- **L1 — Elevated attention**: single divergence detected → increase observer sampling frequency
- **L2 — Rate limit**: divergences in multiple classes → reduce trust in officer findings at scope; require corroboration
- **L3 — Soft arrest**: sustained divergence at critical scope → Regent's action gates require operator co-sign at scope
- **L4 — Hard trip**: chain-reader coherence failure across all members → full Regent arrest; substrate posture set to `chain_view_compromised`; operator ceremony required

Not all divergences escalate. Informational-severity findings inform but don't escalate. Sustained critical findings escalate one level per interval.

## Attack model

- **Attacker corrupts one observer to hide its emitted signal**: coherence discipline detects the divergence between the corrupted observer and the healthy ones. Attacker would need to compromise the *entire* member set of a class to hide the pattern — much higher bar.
- **Attacker corrupts the coherence runtime itself**: runtime is a Layer A subsystem with its own signing key; disabling it requires substrate compromise; runtime heartbeat monitored; sustained absence triggers circuit breaker.
- **Attacker games comparison thresholds via Layer B canonicalization**: threshold changes are chain-anchored ceremony receipts; operator sees them.
- **Attacker floods with false-divergence findings to fatigue operator**: coherence discipline's own resource bounds prevent runaway emission; circuit breaker trip on coherence-scope requires sustained pattern.
- **Attacker seeds ground-truth probe results to lie about arbitration**: ground-truth probes use canonical bypass paths signed with their own Layer A keys; corrupting them requires substrate compromise.

## Non-goals

- **Not a truth referee.** Coherence divergence names who disagreed; it does not decide who's right. Ground-truth arbitration is separate, opt-in, and requires operator delegation.
- **Not a replacement for the observer layer.** Coherence discipline detects observer faults; it doesn't replace the observers themselves.
- **Not real-time blocking.** Divergence findings inform Regent's future cycles and operator dashboard; they don't halt inflight decisions. Blocking behavior belongs to Claim Verifier and Circuit Breaker.
- **Not for external observers.** Substrate cannot cross-check observers outside its own trust boundary. Peer-substrate observation coherence is a separate composition (per peer-verification contract).
- **Not for observers of different underlying state.** Observers in *different* coherence classes (e.g., Steward observing chain vs Sentinel observing network) legitimately produce different views. Cross-class comparison is meaningless.

## Open positions

- **Class membership discovery.** Do new observers auto-register into their declared class, or does the Layer B spec enumerate them explicitly? Prefer explicit for now (auditability); auto-discovery when substrate matures.
- **Cadence tuning.** 5-minute default per class — empirical calibration will refine per class.
- **Ground-truth arbitration cost bounds.** Arbitration probes can be expensive (Class 3 requires syscall bypass, Class 4 requires vault decrypt). Rate-limit and operator-authorize.
- **Divergence severity mapping.** Tail-hash mismatch on Class 1 is Critical; process-count drift by ±2 on Class 3 might be Informational. Per-class empirical calibration.
- **Multi-Form cross-checks.** Should the coherence discipline eventually cross-check between Forms in the same operator's fleet (e.g., Appliance's chain view vs Sovereign's chain view of shared state)? Deferred until Peer Verification Contract implementation matures.
- **Regent-mediated arbitration.** Could Regent use her cognitive layer to reason about which of two divergent observers is more likely correct? Yes but requires care — Regent's own cognition is subject to Cognitive Self-Observer; recursive trust. Prefer operator ceremony for now.
- **Coherence-triggered auto-remediation.** When canary + coherence together identify a specific stuck observer, can the substrate autonomously rebuild that observer's connection? Yes with precedent authorization; escalation ladder per Regent's `act on precedent, escalate on novelty` heuristic.
- **Cross-source observer emitters as a distinct coherence class.** The classes above compare *consumers of the same substrate state*. A novel case surfaces when *multiple observer sources* emit derived signals about the same external subject — most concretely, cross-device face tracking where desktop and mobile trackers both observe the same operator (per OBSERVATION-PLANE-2026-07.md open positions). Coherence probes for source-side observers compare derived signals for consistency rather than reading substrate state; the semantics differ enough from Classes 1–4 to probably warrant its own class (Class 5 — cross-source observer coherence) when the scenario becomes real. Deferred until a second cross-source case exists.

## What composes from here

Immediate design work:

1. Coherence class registry schema (Layer B canonical spec)
2. Probe specifications per class
3. Comparison threshold schemas
4. Finding schema for `coherence:diverged:*` receipts
5. Ground-truth arbitration authorization ceremony receipts
6. Dashboard panel: "Observer coherence" view with per-class agreement history

Near-term implementation:

1. Coherence runtime Layer A in `crates/zp-server/src/coherence/`
2. Per-class probe implementations (start with Class 1 chain readers — highest-value, easiest to test)
3. Comparison logic and finding emission with signing
4. Feedback loop integration — findings flow to Cognitive Input Plane's Tier 2 (substrate state snapshot)
5. Circuit breaker integration — sustained coherence loss escalates through the ladder
6. Composition with canary discipline for combined observer-fault detection

## Framing note

The Cognitive Self-Observer closes the specific gap that today's substrate work exposed: Regent making confident claims about substrate state that don't match ground truth. Observer coherence discipline closes an adjacent, deeper gap: multiple substrate components observing the same underlying state through different code paths, and no discipline to catch when those paths disagree.

The 2026-07-15 P1.1 diagnostic session made this visible: Steward saw "no entries in 658 minutes"; Regent saw "entries throughout the last 30 minutes"; both reading the same live table. Manual operator+external-agent investigation identified the divergence and traced it to a stuck rusqlite Connection. In a mature substrate, the coherence runtime would emit `coherence:diverged:class1_chain_readers` within minutes of the drift, name Steward as the stale observer via ground-truth arbitration, trigger a connection rebuild via canary discipline, and chain-anchor the whole arc. No operator ceremony needed to *detect* the fault — only to authorize the fix.

The load-bearing philosophical claim: coherence is not a property of individual observers; it is a property of the substrate's observation layer as a whole. A single observer confabulates. A substrate that cross-checks observers against each other converts single-observer failure into detectable, correctable, chain-anchored evidence. Coherence is engineered, not hoped for — same discipline as chain integrity, applied to the observation layer that reads the chain.
