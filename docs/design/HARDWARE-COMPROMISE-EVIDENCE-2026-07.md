# Hardware Compromise Evidence — Trigger Capture for Post-Hoc Analysis

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.20 (physical proprioception) and §III.19 (detectability over invulnerability). Specifies the substrate's discipline for capturing raw signals that may reveal SoC / firmware backdoor triggering events — including events whose *meaning as compromise triggers* only becomes visible through post-hoc analysis. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `SOVEREIGN-HARDWARE-2026-07.md` (hardware tiers and per-tier trust chain reach), `HARDWARE-OBSERVER-2026-07.md` (real-time sensor architecture), `OBSERVATION-PLANE-2026-07.md` (observation-scope delegation), `DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md` (community signature exchange), `BLAST-RADIUS-AND-RECOVERY-2026-07.md` (post-detection response).

## Framing

The substrate's threat model includes vendor-level compromise: SoCs shipped with hidden features that only activate under specific triggers; firmware pushed via silent OTA carrying capabilities not present in the reviewed source; management engines that respond to out-of-band signals invisible to the OS. This class of compromise is the primary reason the sovereign-hardware architecture exists — commodity SoCs and closed firmware are structurally opaque to the operator, and the substrate treats that opacity as adversarial.

But there's a temporal problem. When these backdoors are triggered, the substrate may not know it in real time. The event looks like a mild anomaly — a brief power spike, a transient RF signature, an unexplained bus arbitration event, a boot timing shift of a few milliseconds. Alone, each looks like noise. Only later — sometimes months, sometimes years — does a researcher publish a paper describing "the Rowhammer-Adjacent-DMA class" or "the Baseband-Wake trigger" or "the Firmware-N Update-Time Backdoor," and only then can operators go back and check whether their systems showed the newly-recognized pattern.

The Hardware Compromise Evidence discipline is the substrate's structural response to this temporal problem. **Capture the raw signal now, at the highest fidelity storage budget allows. Retain it long enough that post-hoc analysis is possible. Provide retrospective query surface so that new signature patterns can be checked against historical evidence. Exchange signatures with the community so a discovery on one operator's substrate protects the whole federation.**

Three properties frame the discipline:

1. **The trigger event and its identification are temporally separated.** Raw signals are captured continuously; the identification of a specific pattern as a *trigger* may happen later. Capture discipline must not depend on knowing what to look for.
2. **Post-hoc analysis is a first-class use case, not an afterthought.** Retention windows, indexing, retrospective query APIs, and community exchange are designed for the case where the signature is known after the event.
3. **Community exchange multiplies detection power.** A single operator seeing a novel pattern is uncertain about its meaning. A federation seeing the same pattern across multiple operators, correlated with known events (firmware updates, specific workloads, physical proximity), can identify triggers that no single operator could isolate.

## Categories of trigger events

Six categories of events that may retroactively be identified as backdoor triggers:

### 1. Instruction-sequence triggers

Specific instruction sequences, register writes, or MSR accesses that activate hidden SoC features. Examples known from public literature: Intel ME activation sequences, undocumented AArch64 instructions in some ARM cores, hypervisor-mode entry via specific opcode fusion.

Capture: instruction-level tracing is prohibitively expensive continuously; instead, capture *bus-level* signatures — memory-mapped I/O ranges accessed, DMA setup patterns, control register writes to unusual addresses.

### 2. Power-signature triggers

Distinctive power draw patterns that correlate with hidden functionality activation. May appear as micro-spikes during specific workloads, sustained draw during idle, or characteristic ramps during trigger execution.

Capture: high-frequency power rail sampling per HARDWARE-OBSERVER (INA260 or equivalent). Retention of raw power traces for signature-matching windows around anomalous events.

### 3. Thermal-signature triggers

Correlated thermal patterns — specific dies heating in unexpected ratios during trigger execution, GPU/DSP thermals rising during non-graphics workloads, thermal transient patterns matching known covert compute signatures.

Capture: per-sensor thermal history at moderate cadence (1Hz continuous), high-frequency capture (100Hz+) around anomaly detection windows.

### 4. RF-emission triggers

Radio-frequency emissions that reveal covert transmission or receive-mode activation. WiFi/Bluetooth radios silently activated; unauthorized ISM-band or GSM emissions; near-field power transfer to nearby adversary devices.

Capture: broadband RF energy detector continuously monitoring 100kHz-6GHz. Directional antennas noted per HARDWARE-OBSERVER. Spectrograph snapshots on anomaly triggers.

### 5. Timing-anomaly triggers

Boot timing shifts, instruction-latency drifts, DMA arbitration patterns that reveal hidden state machines. Common signature: boot-time inclusion of firmware stages not visible in publicly-declared boot sequence.

Capture: cycle-accurate boot timing per HARDWARE-OBSERVER's boot-timing surface. Comparison against per-firmware-version reference baseline.

### 6. Peripheral / bus-arbitration triggers

Unexpected DMA transactions, unauthorized bus mastering, cache-coherency events matching known side-channel patterns, PCIe TLP patterns that suggest coprocessor activation.

Capture: bus-level activity via observer's PCIe / AXI monitoring (Tier 2+ hardware; Tier 0 commodity Pi has limited bus visibility). USB device enumeration events. Storage controller command patterns.

## Evidence classes

Three evidence classes with different retention and analysis characteristics:

### Class A — Continuous raw signals

Sensor readings at native cadence: power rails (1kHz-10kHz), thermals (1Hz), RF spectrum energy (continuous), boot timing counters (per-boot), bus activity summaries (per-second aggregates).

Retention: 30-90 days rolling window (storage budget dependent), then compressed / summarized. Content-addressed via chain snapshots.

Purpose: retrospective query — "at 03:47:22 UTC on 2026-05-11, what did power rail 3 read?" Fresh signature patterns published post-facto can be checked against this evidence.

### Class B — Anomaly-triggered high-fidelity captures

When any real-time observer flags an anomaly (per HARDWARE-OBSERVER thresholds), capture a windowed high-fidelity snapshot: 60 seconds before, 60 seconds after, all sensor channels at maximum cadence. Store as chain-anchored evidence bundle.

Retention: indefinite (bounded by storage; typical: years). Content-addressed via chain snapshots.

Purpose: forensic evidence packages. Attached to `observer:anomaly:*` receipts; peer-shareable under specific delegation for compromise analysis.

### Class C — Correlated event bundles

When multiple anomalies cluster in time (per correlation-window heuristic), bundle them into a `hardware:event_cluster:<cluster_id>` receipt referencing all Class B evidence packages. Cluster receipts are the primary artifact for post-hoc analysis — they document what happened around the cluster time, letting analysts examine multiple channels together.

Retention: indefinite. Chain-anchored. Peer-shareable.

Purpose: pattern-matching against community signature catalogs; retrospective classification of the cluster as compromise-trigger vs benign.

## The "unknown trigger" problem

Real backdoors are unknown to defenders at capture time. The discipline must produce useful evidence even when the analyst doesn't know what pattern to look for. Three design properties address this:

**Comprehensive raw capture, not filtered capture.** The observer captures broadly at continuous cadence — every rail, every thermal sensor, every RF band. Filtering happens at analysis time, not capture time. A pattern that looks like noise now may be signature later.

**Wall-clock and workload correlation.** Every captured signal is timestamped precisely and cross-correlated with substrate workload state (what the OS was doing, what tools were dispatched, what network activity was in flight). Later analysis needs to distinguish "spike during firmware update" from "spike during idle" from "spike during specific tool invocation."

**Environmental correlation.** Physical context matters: temperature at the moment, humidity, mains voltage, RF environment. Environmental data logged at low cadence continuously. Analysts distinguishing "SoC anomaly" from "environmental influence" need this context.

## Retention discipline

Chain-anchored evidence retention structured by evidence class:

- Class A raw signals: 30-90 day rolling window at native fidelity; then downsampled to reference-baseline granularity for indefinite retention. Downsampling receipts declare what compression was applied so post-hoc analysis knows fidelity limits.
- Class B anomaly captures: indefinite. Storage budget bounded per operator ceremony (e.g., "maintain up to 100GB of Class B evidence; when exceeded, propose oldest packages for archival to peer storage before deletion").
- Class C event clusters: indefinite. Receipts are compact (references + summaries); underlying Class B packages retained per Class B policy.

Retention ceremony: operator can extend retention for specific evidence bundles via `hardware:evidence:retention_extended:<bundle_id>` receipt (e.g., "this bundle references a firmware update event I want to keep permanently"). Chain records the operator's ceremony explicitly.

## Retrospective query surface

Substrate provides retrospective query API:

- **Time-range queries**: "show me all Class B captures between T1 and T2"
- **Signal-range queries**: "show me all evidence where power rail 3 exceeded threshold X"
- **Pattern-match queries**: "show me all evidence matching signature pattern P" (P is a declared pattern from community signature catalog)
- **Correlation queries**: "show me all evidence where thermal anomaly on die 2 coincided with RF event in 2.4GHz band within 500ms"
- **Workload-context queries**: "show me all evidence during firmware update N or within 30 minutes after"

Query interface is a first-class surface, accessible via CLI (`zp hardware evidence query`), dashboard panel, and cognitive input plane (Regent can help operator interpret query results).

## Community signature exchange

Post-hoc analysis is most powerful across a federation. When one operator identifies a pattern that correlates with known-adversary events or matches published research, the pattern becomes candidate for community signature catalog.

**Signature declaration**: pattern declared as `hardware:signature:candidate:<signature_id>` receipt. Fields:
- Pattern description (what to look for in Class B evidence)
- Match criteria (thresholds, time windows, cross-channel correlations)
- Suspected origin (public research citation, community discovery)
- Confidence level (candidate / corroborated / verified)

**Signature distribution**: signatures are peer-shareable under `delegation:share:hardware_signatures` per PEER-TRUST-ANCHOR. Peers can pull candidate and verified signatures into their local catalog.

**Signature verification**: peers running the signature against their own evidence can emit `hardware:signature:corroborated:<signature_id>:<match_evidence_id>` receipts. Multiple corroborations elevate signature from candidate to corroborated to verified.

**Signature retirement**: signatures determined false-positive after further analysis get `hardware:signature:retired:<signature_id>` receipts. Chain preserves the retirement rationale.

**Federation catalog**: the aggregate of shared signatures forms the federation's compromise-signature catalog. Operator can subscribe to signatures from trusted peers; substrate automatically scans local evidence against new signatures as they arrive.

## Regent's role in post-hoc analysis

Regent narrates evidence to operator, cross-references community signatures, and proposes hypotheses.

- "This cluster from three months ago matches signature X (candidate). The signature was published last week. Should I run a match query?"
- "Anomaly cluster K correlates with a firmware update on your device on 2026-05-11. Two peers report similar clusters near their same-model firmware updates."
- "Class B evidence bundle B is being requested by peer P for signature corroboration. Delegation `share:hardware_signatures` covers this. Approve?"

Regent's cognitive delegation for hardware-evidence analysis is scoped: she can narrate, query, and propose. She cannot:
- Delete evidence
- Modify signatures
- Approve peer sharing without operator ceremony
- Interpret evidence as decisive compromise without operator review

Cognitive Self-Observer verifies Regent's evidence-interpretation claims against underlying chain evidence.

## Attack model

Attacker scenarios and how the discipline addresses them:

- **Attacker aware of retrospective analysis capability**: attacker may design triggers that produce minimal evidence signatures. Substrate captures broadly so subtle signatures still appear even when not designed to. Comprehensive coverage limits attacker's ability to move entirely below detection floor.
- **Attacker manipulates evidence post-capture**: chain integrity prevents modification of captured evidence. Class B bundles are chain-anchored with content hashes.
- **Attacker suppresses evidence at capture**: hardware observer's independence (separate power, crystal, signing) per HARDWARE-OBSERVER prevents SoC-level suppression. Observer emits heartbeats; silence itself is a signature.
- **Attacker exploits knowledge of signature catalog**: some signatures are peer-shared and effectively public. Attacker knows what's being looked for. But signature catalog is one channel among comprehensive raw capture — attacker suppressing known-signature-targeted patterns may still leave broader anomalies.
- **Attacker uses novel triggers no signature covers**: this is the primary threat model post-hoc analysis addresses. Comprehensive raw capture means when future research identifies the trigger, the evidence is retrospectively available.
- **Attacker floods substrate with fake anomalies to bury real ones**: rate limits on anomaly-triggered Class B captures; storage budget triggers operator ceremony rather than automatic deletion; anomaly clustering deduplicates flood patterns.
- **Attacker delays post-hoc analysis via peer isolation**: federation of peers each running signature catalog and cross-checking evidence provides resilience against isolation of any single peer.

## Failure modes

- **Storage budget exceeded**: retention policies apply; oldest Class A raw signals compressed first; if further exceeded, operator ceremony required to authorize archival deletion. Substrate does not silently discard evidence.
- **Signature false positive rate high**: patterns that trigger frequent false matches lower catalog signal quality. Peer verification thresholds and community reputation manage this.
- **Post-hoc analysis inconclusive**: evidence is captured but analysis cannot definitively classify a cluster as compromise or benign. Cluster stays open in chain state; may resolve later when more evidence accumulates or better signatures emerge.
- **Community signature catalog compromised**: attacker-inserted signature designed to point away from real backdoors. Federation reputation, cross-verification requirements, and operator override protect against single-signer catalog poisoning.
- **Evidence retention gap**: for time periods before observer was deployed, no evidence exists. Pre-observer periods are structurally unrecoverable. Chain records observer deployment ceremony so pre-deployment gaps are visible.
- **Observer itself compromised**: per HARDWARE-OBSERVER, observer has independent power and signing. If observer signing key is compromised, evidence from that observer becomes suspect from compromise point forward. Genesis rotation ceremony re-provisions observer keys.

## Composition with existing discipline

**With HARDWARE-OBSERVER-2026-07.md**: this spec defines *what to preserve* from observer captures for post-hoc analysis. Observer captures signals; this discipline retains and structures them for retrospective analysis.

**With OBSERVATION-PLANE-2026-07.md**: hardware evidence is one class of observation. Observation-scope delegation applies to hardware evidence access — sharing evidence with peers requires scoped delegation.

**With BLAST-RADIUS-AND-RECOVERY-2026-07.md**: when post-hoc analysis identifies compromise trigger, response follows blast-radius discipline. Circuit breaker escalation, quarantine of suspect hardware, forward-only recovery.

**With DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md**: signature catalog is a form of shared knowledge; commons discipline applies. Reputation, trust anchors, peer-verified corroboration.

**With GENESIS-ROTATION-CEREMONY-2026-07.md**: identification of compromise may trigger Genesis rotation for the affected sovereign. Historical evidence pre-rotation remains valid; new evidence post-rotation is under new Genesis authority.

## Non-goals

- **Not real-time compromise prevention**. This discipline addresses the temporal gap between capture and identification. Real-time detection is the observer's job; this discipline captures for the case where real-time detection missed.
- **Not universal forensic capability**. Substrate captures what its observer surfaces reach. Below-observer compromises (SoC internals with no external signature) are structurally invisible. The observer architecture aims to maximize external signature coverage, but perfection is unachievable at commodity tiers.
- **Not automated compromise remediation**. Post-hoc identification triggers ceremony (operator review, potential Genesis rotation, circuit breaker). Substrate does not autonomously respond to retrospectively-identified compromise.
- **Not a substitute for hardware security research**. Substrate captures evidence that researchers can analyze. Research itself — identifying trigger classes, publishing signatures — happens in the security research community. Substrate is the evidence infrastructure.
- **Not universal signature catalog**. No single catalog covers all possible triggers. Community catalog is aggregated best-effort; gaps exist by definition.

## Open positions

- **Storage budget policy defaults**. What's reasonable for 30/60/90 day rolling window at native cadence? Scales with observer sensor count.
- **Anomaly-trigger threshold defaults**. When does Class A native capture become Class B high-fidelity bundle? Trade-off between missing subtle events and drowning in Class B storage.
- **Peer signature sharing granularity**. Do peers share full evidence bundles or only signature patterns? Signature patterns are compact but may miss context; full bundles are large but complete.
- **Long-term archival strategy**. Beyond active substrate storage, how is very-old Class A evidence archived? Peer archival network? Cold storage? Operator decision per ceremony.
- **Signature language expressiveness**. Simple threshold matching is easy; complex temporal-correlation patterns need a signature DSL. Design work.
- **Evidence discovery UX**. How does operator explore evidence at retrospective query time? CLI, dashboard, Regent-narrated exploration?
- **Automated re-scan on new signatures**. When new signature arrives from community, should substrate auto-scan all historical Class B evidence? Compute cost vs coverage.
- **Firmware-update correlation**. Firmware updates are high-suspicion events. Automatic evidence capture windows around firmware updates? Cadence?
- **Cross-vendor observability equivalence**. Different SoC vendors expose different external signatures. Signature catalog needs per-vendor sensitivity. How is this managed at federation scale?

## What composes from here

Immediate design work:

1. **Evidence bundle schema**: content-addressed Class B captures, Class C cluster receipts
2. **Retention policy runtime**: rolling window management, budget enforcement, ceremony gates
3. **Retrospective query API**: SQL-adjacent or purpose-built query language for time-range, signal-range, pattern-match, correlation
4. **Signature language spec**: DSL for expressing compromise-trigger patterns
5. **Community catalog exchange protocol**: peer signature share, corroboration receipts, catalog subscription

Near-term implementation:

1. Evidence retention layer in `crates/zp-server/src/hardware/evidence/`
2. Class A rolling window over observer sensor stream
3. Class B anomaly-triggered high-fidelity capture pipeline
4. Class C correlation clustering runtime
5. Chain-anchored evidence storage with content-addressed bundles
6. Retrospective query CLI: `zp hardware evidence query`
7. Dashboard hardware evidence panel
8. Community signature catalog protocol implementation

## Framing note

Hardware compromise evidence capture is the substrate's structural response to the temporal gap between compromise event and compromise identification. Same principle as chain-anchored discipline for other trust boundaries — extended to evidence-preservation for retrospective analysis.

The load-bearing insight: **the substrate cannot detect what it hasn't captured, and it cannot know at capture time what will later prove to be signal.** Comprehensive raw capture, chain-anchored retention, retrospective query surface, and community signature exchange together make post-hoc analysis structurally possible. When a trigger pattern becomes recognizable — through public research, community discovery, or peer correlation — the evidence exists to check retroactively.

Combined with the substrate's structural discipline across every trust boundary — actions, admissions, observations, cognition, extensions, hardware, emergency response, Genesis rotation, peer trust, build lifecycle, reproducibility, recovery UX, standing corrections — hardware compromise evidence capture completes the temporal envelope for hardware sovereignty. What today's SoC/firmware threat model requires (defending against attackers whose triggers we don't yet know how to recognize) becomes structurally possible when raw evidence is preserved, federation-shared, and retrospectively queryable. Detectability extends across time: what silence looks like today may become named signal tomorrow, and the substrate is ready for that reveal because it captured the raw signal all along.
