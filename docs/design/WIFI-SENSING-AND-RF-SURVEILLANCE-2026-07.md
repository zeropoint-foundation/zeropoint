# WiFi Sensing and RF Surveillance

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.15 (substrate boundary planes), §II.20 (physical proprioception), §III.18 (delegable safety), and §III.19 (detectability over invulnerability). Specifies the substrate's discipline for the two faces of RF sensing: adversarial external CSI surveillance (attackers using WiFi Channel State Information to infer operator state), and delegable operator-facing sensing capability (operator using their own radios to observe their environment under scoped delegation). Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `HARDWARE-COMPROMISE-EVIDENCE-2026-07.md` (RF-emission trigger category and evidence discipline apply here too), `OBSERVATION-PLANE-2026-07.md` (sensing is an observation surface with scope-delegation), `EXTENSION-SURFACE-2026-07.md` (sensing capabilities are extension implementations), `QUARANTINE-PLANE-2026-07.md` (sensing extensions require admission ceremony), `HARDWARE-OBSERVER-2026-07.md` (broadband RF energy detector is one of the observer's sensor classes).

## Framing

WiFi Channel State Information (CSI) is the physical-layer measurement of how radio signals propagate through space. Modern WiFi chipsets extract CSI per-subcarrier for beamforming and multipath compensation. That same data reveals the physical environment: motion changes CSI patterns; presence changes them; even respiration and keystrokes have been shown to leave characteristic signatures. A passive receiver within RF range of an operator's WiFi network can, without associating and without transmitting, extract enough CSI variation to infer high-level information about who is in the room, what they're doing, and — with sufficient training data and target-specific fingerprinting — what they're typing.

The substrate faces this reality on two faces simultaneously. **As target**: the operator's environment is potentially CSI-legible to anyone nearby with a modified WiFi radio. This is not exotic hardware; consumer chipsets with modified firmware suffice. Detection of adversarial CSI probing is a first-class threat model. **As potential emitter and sensor**: the substrate's own radios both emit CSI-legible signals AND could be delegated to sense the operator's environment (intrusion detection, occupancy sensing, gesture input). Both need discipline: minimize adversarial legibility of substrate's own emissions; scope-delegate operator-facing sensing capability so it composes with the trust envelope rather than opening a bypass.

Three properties frame the discipline:

1. **RF-sensing is bidirectional infrastructure**. The same radios that could sense the environment also emit signals that reveal the environment to others. Discipline governs both directions.
2. **Adversarial detection and delegable capability share substrate infrastructure but need opposite orientation**. Detection minimizes emission and maximizes reception; capability requires operator-authorized emission and reception at scoped grants. Both live on the same hardware but under separate delegations.
3. **CSI-legibility is a substrate hygiene concern, not just a per-extension concern**. Every substrate radio transmission is potentially CSI-legible. Emission discipline is a substrate-wide invariant, not something individual extensions decide.

## The adversarial threat model

What a nearby passive attacker can infer from ambient CSI:

- **Presence and occupancy**: how many people are in the room, roughly where they are, when they enter and leave. Widely documented; commodity chipsets suffice.
- **Motion patterns**: walking, sitting, standing, hand gestures at coarse resolution. Well-studied academic literature.
- **Respiration rate**: chest movement modulates CSI at breathing frequency. Requires stationary target.
- **Keystroke inference**: with target-specific fingerprinting (attacker has trained on target's typing patterns on this specific keyboard in this specific spatial arrangement), individual keys become distinguishable. High effort but demonstrated.
- **Device fingerprinting**: what wireless devices are present, their manufacturer profiles, their RF behavior signatures. Passive; no association needed.
- **Behavioral correlation**: correlating CSI patterns with time-of-day, calendar events, and other observations to infer operator schedule and habits.

Attacker positions:

- **In-range neighbor**: apartment next door, adjacent office, parked vehicle. Passive listening; no infrastructure needed beyond a modified WiFi card.
- **Compromised nearby device**: a smart speaker, a neighbor's router, an IoT device with modified firmware. Bootstraps into the CSI-legible position without physical presence.
- **Rogue AP**: attacker deploys their own AP nearby, either passively sniffing or actively transmitting to elicit reflections.
- **Compromised operator infrastructure**: operator's own WiFi router firmware compromised; router exports CSI to attacker. This composes with HARDWARE-COMPROMISE-EVIDENCE — router firmware compromise is one class of trigger.

## Detection of adversarial CSI probing

Signature classes for adversarial CSI activity:

### Class 1 — Anomalous nearby AP behavior

Attacker's active CSI probing often involves unusual traffic patterns: probe request bursts at atypical rates, beacon irregularities, association attempts targeting specific channels. Substrate observer (via HARDWARE-OBSERVER's RF surface) can log ambient AP behavior and flag anomalous patterns.

### Class 2 — Rogue AP fingerprints

Known CSI-extraction firmware modifications (nexmon, OpenWrt CSI patches, Atheros ath9k modifications) produce identifiable RF signatures — beacon timing quirks, capability advertisement irregularities, response patterns. Community signature catalog per HARDWARE-COMPROMISE-EVIDENCE distributes these fingerprints.

### Class 3 — Probing correlation with operator presence

Sophisticated attackers probe more intensely when operator is present (to gather higher-value data) and back off during operator absence. Cross-correlation of nearby AP activity with operator presence patterns can reveal targeted surveillance. Requires substrate to have an independent presence signal (not CSI-derived, to avoid circularity — HARDWARE-OBSERVER's tamper switches, boot-detection surfaces, or peer-substrate presence signals).

### Class 4 — RF proximity of unauthorized devices

Directional antennas or triangulation from multiple observation points can localize unauthorized devices. Detection of persistent unauthorized RF sources within the operator's physical space is signature-worthy. Community catalog distributes known adversary-device RF fingerprints.

### Class 5 — Coordinated multi-band activity

CSI extraction often correlates with activity in other RF bands (e.g., attacker using Bluetooth or LTE for exfiltration while WiFi handles sensing). Cross-band correlation increases signature confidence.

Detection outputs are chain-anchored `wifi:adversarial_probing:*` receipts. Class B evidence bundles (per HARDWARE-COMPROMISE-EVIDENCE) capture high-fidelity RF around detection events for retrospective analysis.

## Substrate's own RF emission discipline

Every substrate radio transmission is a potential CSI-legible signal to nearby adversaries. Emission discipline is substrate-wide, not extension-specific.

Three emission modes, delegable per operator ceremony:

### Mode A — RF Quiet

Substrate suppresses discretionary radio transmissions. Only chain-critical emissions (peer sync at negotiated intervals, emergency communications) occur, and even those emit under randomized timing to reduce fingerprint predictability.

Delegation grant: `delegation:rf:quiet_mode:granted`. Chain-anchored. Substrate defaults to this mode in high-threat contexts (operator declares physical threat concern; operator is at unfamiliar location; hardware observer reports adversarial-probing signals).

### Mode B — Standard

Substrate transmits per normal operational patterns. Peer sync, tool dispatches, dashboard interactions occur without additional CSI-hardening. Default for most operator environments.

### Mode C — Sensing-Enabled

Substrate's own radios emit patterns that support CSI-based sensing of the operator's own environment. This mode inherently makes the substrate more CSI-legible to adversaries because active sensing requires more RF activity. Delegation grant: `delegation:rf:sensing_enabled:granted:<sensing_capability>`. Chain-anchored per specific sensing use (intrusion detection, occupancy, etc.).

Operator moves between modes via ceremony. Chain records mode transitions. Cognitive Self-Observer flags Regent-narrated proposals that assume wrong emission mode.

## Delegable operator-facing sensing capability

Operator-facing WiFi CSI sensing is an Extension Surface implementation per EXTENSION-SURFACE-2026-07.md. Extensions declare `capability:sense:rf:csi` and go through Quarantine Plane admission ceremony.

### Capability class declaration

`capability:sense:rf:csi` declares:
- Uses substrate's WiFi radios in receive mode for CSI extraction
- Requires Mode C (Sensing-Enabled) delegation on the substrate
- Requires scoped operator delegation for specific sensing use (intrusion detection, occupancy, gesture input, etc.)
- Emits `sensing:csi_finding:*` receipts — filtered high-level findings only, never raw CSI streams
- Retains raw CSI in Extension-managed encrypted storage; findings are chain-anchored

### Extension admission

Extension implementing CSI sensing goes through Quarantine Plane per QUARANTINE-PLANE-2026-07.md:

1. Intake — extension binary declared with capability requirements
2. Verification — signature check, capability declaration review
3. Operator delegation — ceremony granting `capability:sense:rf:csi` at declared scope
4. Admission — extension activated, substrate emits `wifi:sensing_capability:activated:<extension_id>` receipt
5. Asymmetric revocation — operator can revoke without ceremony; re-admission requires ceremony

### Cognitive-layer boundary

Raw CSI never enters cognitive layer. Extension emits high-level findings ("presence detected in zone 3," "unusual motion pattern at 03:47") which reach Regent through cognitive input plane per COGNITIVE-INPUT-PLANE. Raw CSI is retained in extension-managed encrypted storage for extension-internal use (fingerprint refinement, historical comparison) and never transmitted to peers or cognitive layer.

This boundary is load-bearing: raw CSI is inherently privacy-sensitive (contains motion, occupancy, potentially keystroke information about operator's household). Cognitive layer operates on findings, not on raw sensing signals.

### Sensing surface types

Extensions can implement any of these sensing use cases as declared capability sub-classes:

- **Presence**: room-level occupancy detection. Findings: "presence: zone 3, high confidence, 08:47Z"
- **Motion**: motion tracking within known zones. Findings: "motion: zone 1 → zone 2, sustained 5s"
- **Intrusion**: motion at unexpected times/zones. Findings: "unexpected motion: zone 3, no scheduled activity"
- **Occupancy count**: rough headcount. Findings: "occupancy: 2-3 people, zone 1"
- **Vitals** (respiration, heartrate): only under explicit high-scope delegation. Findings: "respiration: normal range, sleep pattern"
- **Gestures**: gesture recognition for accessibility or input. Findings: "gesture: recognized 'pause', high confidence"

Each sub-class requires its own operator ceremony grant. Broad delegation ("any CSI sensing") is discouraged; substrate defaults to narrow per-capability grants.

## Cross-referencing with hardware compromise evidence

HARDWARE-COMPROMISE-EVIDENCE captures broadband RF continuously as Class A evidence. WiFi-sensing-and-RF-surveillance discipline extends the RF-emission trigger category with specific CSI-adversarial signature classes.

Concretely: `wifi:adversarial_probing:*` receipts emitted by this discipline are also candidate for HARDWARE-COMPROMISE-EVIDENCE's Class C event clusters when they cluster with other trigger classes (e.g., a firmware update immediately followed by anomalous CSI probing suggests compromise + surveillance sequence). Community signature catalog (per HARDWARE-COMPROMISE-EVIDENCE) hosts CSI-surveillance signatures alongside other hardware compromise signatures.

Sharing infrastructure with HARDWARE-COMPROMISE-EVIDENCE means CSI-adversarial detection benefits from federation-level signature exchange without requiring separate distribution mechanism.

## Regent's role

Regent's role for RF sensing surfaces is bounded to narrative and advisory:

- Explaining findings from sensing extensions ("presence extension reports unusual motion pattern in zone 3 at 03:47")
- Explaining detected adversarial probing signals ("nearby AP has been probing anomalously for 20 minutes; matches signature X candidate from community catalog")
- Proposing emission mode transitions ("adversarial signals suggest RF Quiet mode; requires operator ceremony")
- Cross-referencing sensing findings with other substrate state ("motion in zone 1 coincides with no logged activity — investigate?")

Regent cannot:
- Directly access raw CSI streams (cognitive-layer boundary)
- Change emission mode without operator ceremony
- Admit new sensing extensions
- Modify sensing capability scope
- Suppress `wifi:adversarial_probing:*` receipts

## Attack model

Attacker scenarios and how the discipline addresses them:

- **Passive CSI extraction from neighbor position**: signature-based detection catches probing patterns; community catalog distributes fingerprints; operator can transition to RF Quiet mode.
- **Compromised nearby device (smart speaker, IoT)**: signature-based detection catches anomalous RF activity from device; PEER-TRUST-ANCHOR discipline governs whether device is admitted as observation reference.
- **Rogue AP deployed at physical proximity**: RF direction-finding and community fingerprints detect known rogue AP firmware; operator receives high-priority `wifi:rogue_ap:detected` receipt.
- **Attacker compromises operator's own router firmware for CSI exfiltration**: router firmware compromise is a HARDWARE-COMPROMISE-EVIDENCE concern; observed via anomalous outbound traffic patterns, router configuration drift, boot-time anomalies. Compromised router does not have delegated `capability:sense:rf:csi`; any CSI-relevant activity from it is out-of-scope and flags as violation.
- **Attacker exploits substrate's own Sensing-Enabled mode**: substrate in Mode C is more CSI-legible. Mode C is opt-in per operator ceremony; substrate reminds operator of the trade-off; adversarial-probing detection continues to run in Mode C so operator can respond if surveillance is detected.
- **Attacker fingerprints substrate's own RF emissions**: even in Mode A (RF Quiet), substrate has some emission profile. Emission timing randomization reduces predictability; fully unfingerprintable emission is not achievable. Operator physical-layer discipline (Faraday enclosures, RF-shielded rooms) is a further mitigation outside substrate scope.
- **Extension implementing CSI sensing exceeds declared capability scope**: extension attempts sensing operations beyond its grant. Extension Surface enforcement per EXTENSION-SURFACE catches this; violation receipt; ceremony required to re-authorize (typically: revoke and re-admit with clarified scope).
- **Sensing findings inferred from raw CSI reveal more than operator authorized**: extension emits high-level finding that inadvertently contains information beyond declared scope. Cognitive Self-Observer verifies findings against extension's declared scope; violations flagged.

## Failure modes

- **False positive on adversarial probing**: normal WiFi environment produces occasional anomalies. Signature confidence levels distinguish; community catalog corroboration filters. Operator UX presents candidate detections with confidence, not decisive alerts.
- **CSI sensing extension has poor accuracy**: findings unreliable; operator loses confidence. Extension reputation via commons; peer verification of extension capabilities; operator can revoke and try alternate extensions.
- **Mode C sensing infrastructure conflicts with adversarial detection**: substrate emitting more RF is more legible to adversaries. Trade-off is inherent; operator chooses per ceremony; substrate surfaces the trade-off before mode transition.
- **Raw CSI storage exceeds budget**: extension retains too much raw CSI; storage pressure. Extension-side retention policy declares limits; substrate enforces via Extension Surface capability-class quotas.
- **Peer sharing of CSI findings inadvertently reveals operator state**: findings shared to peers contain more information than operator intended. Delegation for CSI-finding sharing is per-peer per-finding-class; operator ceremony gates each sharing class.

## Non-goals

- **Not universal RF privacy**. Physical shielding (Faraday enclosures, RF-shielded rooms) is a stronger mitigation than substrate discipline for high-threat environments; substrate discipline is complementary, not substitute.
- **Not perfect CSI-adversarial detection**. Novel probing patterns won't match existing signatures; comprehensive raw RF capture per HARDWARE-COMPROMISE-EVIDENCE enables post-hoc identification.
- **Not automatic emission-mode transition**. Substrate does not autonomously enter RF Quiet mode based on detected threats; operator ceremony required. Substrate proposes; operator signs.
- **Not extension-provided cognitive access to raw CSI**. Cognitive-layer boundary is invariant; extensions expose findings, not raw signals, to Regent regardless of extension declaration.
- **Not defense against physical-layer capture with cryptanalytic effort**. If attacker records raw RF at high fidelity and applies substantial post-processing, some sensitive information may be extractable regardless of substrate discipline. Physical operational security remains an operator concern.

## Open positions

- **Emission mode default per Substrate Form**. Sovereign Form default: standard. Companion Form default: standard (vendor OS may emit regardless). Should high-threat operator profiles default to RF Quiet? Operator preference vs safety trade-off.
- **Randomization discipline for chain-critical emissions**. Chain sync intervals are structurally periodic; randomization reduces fingerprintability but adds latency. How much randomization is right?
- **Sensing capability sub-class taxonomy**. Presence, motion, intrusion, occupancy, vitals, gestures — are there other classes? How fine-grained should sub-classes be?
- **Extension retention limits for raw CSI**. What's a reasonable per-extension limit? Storage budget interaction with HARDWARE-COMPROMISE-EVIDENCE Class A retention.
- **Peer sharing granularity for CSI-adversarial findings**. When operator's substrate detects adversarial probing, should nearby peers automatically be notified (physical proximity awareness)? Delegation model for physical-proximity signal sharing.
- **Multi-radio coordination**. Substrate may have multiple RF interfaces (WiFi, Bluetooth, LTE, LoRa). Emission discipline coordinates across all radios or per-radio?
- **Sensing extension marketplace**. If operator wants intrusion detection, do they audit each candidate extension themselves, or does community reputation via commons drive selection? Extension-selection UX design.
- **Direction-finding accuracy at commodity hardware**. Tier 0 (Pi 5) has limited direction-finding capability. Higher tiers (custom carriers with antenna arrays) enable localization. Per-Tier capability declaration.

## What composes from here

Immediate design work:

1. **Adversarial probing signature schema**: Layer B canonical spec for the CSI-surveillance signature classes
2. **Emission mode receipt schemas**: mode transitions, delegation grants, ceremony flow
3. **CSI sensing capability class spec**: `capability:sense:rf:csi` and sub-classes for Extension Surface
4. **Extension trait interface for sensing**: `Sensor` trait extension supporting CSI extraction with declared-scope findings
5. **Cognitive-layer boundary enforcement**: how substrate ensures raw CSI never reaches Regent

Near-term implementation:

1. Emission mode manager in `crates/zp-server/src/rf/emission_mode/`
2. CSI adversarial probing detector (integrated with HARDWARE-COMPROMISE-EVIDENCE Class B pipeline)
3. Extension Surface capability declarations for sensing sub-classes
4. Community signature catalog integration for CSI-surveillance signatures
5. Dashboard RF-mode panel showing current emission mode, adversarial-probing status, sensing extensions active
6. CLI verbs: `zp rf mode set|status`, `zp rf sensing list|grant|revoke`, `zp rf probing status|history`

## Framing note

WiFi sensing and RF surveillance discipline addresses the two faces of RF as substrate infrastructure: the substrate as adversarial target (nearby attackers may passively sense the operator) and the substrate as delegable sensor (operator may authorize sensing extensions for their own use). Same underlying infrastructure; opposite orientation; both need explicit discipline.

The load-bearing insight: **RF-sensing is bidirectional infrastructure that must be operator-authorized in both directions.** Emission discipline (substrate's own radios) is a substrate-wide invariant with chain-anchored mode transitions. Sensing capability (extensions using radios for operator benefit) is scope-delegated per Extension Surface. Adversarial detection composes with HARDWARE-COMPROMISE-EVIDENCE for federation-level signature exchange. Cognitive-layer boundary keeps raw CSI privacy-sensitive information out of the Regent's reasoning context regardless of extension declaration.

Combined with the substrate's structural discipline across every trust boundary, WiFi sensing discipline closes one specific attack surface (ambient RF surveillance) while opening a specific legitimate capability class (operator-authorized environment sensing). What was previously implicit — the substrate emits and receives RF; anyone nearby can measure it — becomes explicitly chain-anchored: emission mode is operator ceremony; sensing capability is scoped delegation; adversarial detection is signature-catalog integration; raw signals stay behind the cognitive boundary. Sovereignty is preserved because operator authorizes both faces; safety is preserved because detection continues across all modes; continuity is preserved because chain records every mode transition, every delegation, every detection event.
