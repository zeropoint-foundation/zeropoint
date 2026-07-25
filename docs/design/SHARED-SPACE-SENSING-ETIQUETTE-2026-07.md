# Shared-Space Sensing Etiquette

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.15 (substrate boundary planes), §II.20 (physical proprioception), §III.18 (delegable safety), §III.19 (detectability over invulnerability), §III.23 (coordination, not oversight). Specifies the substrate's discipline for behavior in shared physical spaces with strangers — bystander-controlled signaling protocol, space-declared norms, emission discipline for the substrate's own RF-legible signals, and the strict boundary against categorical review of non-kindred sovereigns. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `WIFI-SENSING-AND-RF-SURVEILLANCE-2026-07.md` (adversarial detection and substrate's own emission modes), `SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md` (kindred sovereigns in shared space with strangers), `PEER-TRUST-ANCHOR-2026-07.md` (trust anchor discipline for stranger substrates), `DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md` (space-declared norms as commons artifacts), `OBSERVATION-PLANE-2026-07.md` (observation-scope delegation constrains stranger observation), `HARDWARE-COMPROMISE-EVIDENCE-2026-07.md` (adversarial signature catalog integration), `EXTENSION-SURFACE-2026-07.md` (sensing extensions operate under scoped delegation in shared contexts).

## Framing

The mass-adoption horizon has every sovereign carrying a substrate node. In shared physical spaces — cafes, transit, offices, streets, apartment buildings — everyone is emitting CSI-legible signals AND everyone's substrate could sense the environment. The population-scale reality collapses the "operator vs adversary" distinction that individual-scale threat modeling assumes. Most CSI-sensing activity in a room full of substrate-carrying sovereigns is from legitimate substrates, not attackers. Most emitters are legitimate operators, not surveillance devices. This changes what discipline is needed.

Standardization landscape as of 2026: IEEE 802.11bf shipped September 2025 without privacy protections for non-participating individuals — no consent framework, no opt-out, no mandatory disclosure. The proposed waveform-layer countermeasure was documented in the committee's own threat analysis, formally proposed in Letter Ballot 272 (comments 2226-2229), and never converged on. 3GPP Release 19 for 5G required the equivalent protection; WiFi did not. Consumer chipsets shipping 802.11bf-compliant sensing are landing at commercial scale through 2026-2027. The regulatory vacuum around passive CSI extraction remains open.

Substrate discipline in shared spaces addresses this landscape structurally. Three properties frame the discipline:

1. **Substrate does not categorically observe strangers.** Substrate operators are sovereigns, not bystanders. Substrate's observation surface for strangers is bounded by design: presence detection at anonymized zone-level for the operator's own coordination, adversarial-probing detection for defense, and nothing more. No identification of strangers. No retention of stranger-linked evidence beyond adversarial-signature classes. No cross-referencing to build stranger identity graphs.
2. **Bystander signaling is bystander-controlled.** Following the BlindSpot inversion (Dec 2025) — bystanders signal preference; sensing substrates receive and comply. Chain-signed short-range beacons declare bystander sensing preferences; substrates that sense while receiving compliance signals commit chain-visible norm violations. Signaling primitive is under the bystander's sovereignty, not the sensor's.
3. **Space norms are commons-declared, substrate-honored.** Physical spaces publish sensing norms via commons registry, physical beacon, or QR code at entry. Substrates observe declared norms and adjust posture accordingly — RF emission mode, sensing intensity, extension activation. Norms are commons artifacts; substrate is norm-consumer, not norm-arbiter.

## What substrate does NOT do in shared spaces

Coordination-not-oversight discipline (KEEL III.23) applied to shared spaces produces a specific list of things the substrate structurally does not do, regardless of operator authorization:

- **Does not identify strangers.** Presence detection is possible; identification of specific strangers by their substrate signature is not offered as a primitive. Substrate cannot answer "who is that person in zone 3." It can answer "presence detected in zone 3" or "unknown substrate detected." No operator authorization unlocks identification of strangers.
- **Does not build stranger relationship graphs.** Substrate does not accumulate records of "operator has been in same space as unknown sovereign X on N occasions." No pattern-matching stranger encounters into implicit relationships. No commons-shareable "here are people the operator co-encounters frequently."
- **Does not retain stranger-linked evidence categorically.** HARDWARE-COMPROMISE-EVIDENCE Class B captures anomalies triggered by adversarial patterns; those retentions are signature-linked, not stranger-linked. Stranger-linked retention (a specific stranger's presence over time in operator-adjacent spaces) is not a substrate primitive.
- **Does not narrate stranger observations to Regent as identifying context.** Regent's cognitive input plane admits "presence in zone 3" (anonymized); does not admit "the person who was here yesterday is here again" (implicit identification). Cognitive Self-Observer verifies that Regent's outputs don't identify strangers even from ambient patterns.
- **Does not share stranger observations to peers under any trust anchor.** Sensing findings shared under `emergency_notification` or `mutual_safety_check` are operator-context-scoped. Strangers observed as ambient noise are not part of shareable content.
- **Does not enable extensions to bypass these constraints.** Extensions declaring sensing capabilities operate within the same substrate-wide invariants. An extension attempting to identify strangers or build stranger graphs is out-of-scope regardless of capability declaration; Quarantine Plane admission ceremony catches capability declarations that violate substrate invariants.

These are structural. They are not privacy features the operator can toggle off. They are the substrate's shape.

## Bystander signaling protocol

Following the BlindSpot inversion, the sovereign bystander is the party with the signal. The sensing substrate is the party that must receive and comply.

### Bystander preference beacon

Sovereign bystanders (those who don't want to be sensed by nearby substrates) emit chain-signed short-range signaling declaring their preference. Signaling modalities:

- **BLE beacon** with substrate-standard payload declaring preference class
- **UWB tag** with substrate-standard payload (higher-precision proximity, useful when many bystanders present)
- **Optional VLC** (visible light communication) — for high-visibility declaration in cases where the bystander wants overt indication
- **Manual signal** — a chain-signed hand-gesture-triggered emission from the operator's substrate under specific delegation

Preference classes (initial canonical set):

- `bystander:signal:no_sense` — bystander prefers not to be sensed by any nearby substrate
- `bystander:signal:presence_only` — bystander accepts anonymized presence detection, refuses biometric or activity sensing
- `bystander:signal:default` — no explicit preference declared (substrate uses space norms or its own defaults)

Signals include: bystander's Genesis-signed authorization, timestamp (for replay-attack prevention), and preference class. Substrates observing the signal verify the signature and comply.

### Substrate compliance discipline

Substrate configured with sensing extensions or operating in Mode C (Sensing-Enabled) per WIFI-SENSING must:

- Continuously scan for bystander preference beacons in its sensing scope
- Verify beacon signatures against chain integrity
- Apply preference class to sensing operations before the sensing runs (not after — compliance is preemptive)
- Emit `substrate:bystander_signal_honored:<beacon_id>` receipt for each honored signal (chain-anchored evidence of compliance)

Failure to comply is a chain-visible norm violation. Substrates that sense while receiving `no_sense` signals emit — or fail to emit — `substrate:bystander_signal_ignored:<beacon_id>` receipts either through the substrate's own honest chain-anchoring or through community signature-catalog detection of non-compliance patterns.

### Bystander signal authenticity

Sovereign bystanders' beacons are chain-signed. Attacker cannot forge bystander preference on behalf of others (would require target's Genesis compromise). Bystander can revoke their own beacon at any time.

Non-sovereign bystanders (people without substrate infrastructure) cannot emit chain-signed beacons. This is a real gap: the substrate discipline protects sovereigns; non-sovereigns rely on other mechanisms (regulation, space norms, physical shielding). Substrate does not close this gap alone — it operates as one component in a broader civil-society posture.

## Space-declared norms

Physical spaces declare sensing norms that apply to all substrates present. Norms are commons artifacts per DISTRIBUTED-KNOWLEDGE-COMMONS.

### Norm declaration surfaces

Norms are declared via:

- **Physical beacon** at space entrance (BLE, UWB) broadcasting the space's declared norm URI
- **QR code** at space entry with declared norm URI (operator's substrate scans on request)
- **Geographic commons registry** for spaces without physical beacon (substrate looks up geographic coordinates against commons registry)
- **Substrate-composed defaults** when no space-declared norm found (e.g., "unknown-space default: presence-only, no retention")

Norm declarations are commons-hosted; commons trust anchor discipline governs which norm publishers substrate trusts.

### Norm content

Norms specify per-class sensing acceptability within the space:

- Presence detection: allowed / bystander-signal-required / prohibited
- Biometric sensing: allowed / consent-required / prohibited
- Retention: no-retention / ephemeral / bounded / operator-discretion
- Identification: prohibited (default across all norms; norms cannot override this substrate invariant)
- Adversarial-probing detection: always allowed (substrate invariant)
- Emission mode expectation: RF Quiet / Standard / permitted-Sensing-Enabled

Some spaces will declare very-restrictive norms (hospitals, courthouses, worship spaces, mental-health facilities): presence-only, no retention, RF Quiet mode required. Some will declare permissive norms (private homes with operator consent, sports venues): standard defaults.

### Norm compliance

Substrate observes declared norms via:

- Scanning for space beacons at entry
- Querying commons registry against operator's geographic position
- Composing "unknown-space defaults" when no norm declared

Substrate emits `substrate:space_norm_observed:<space_id>:<norm_id>` receipt when applying a norm. Emits `substrate:space_norm_departed:<space_id>` when leaving the space's scope. Chain records the compliance arc.

Compliance is preemptive: substrate applies restrictive-norm sensing posture before entering, not after. When substrate transitions between spaces with different norms, the more restrictive norm applies during transition.

### Norm publisher discipline

Anyone can declare norms for their space (they are the sovereign of that space, at some level). Substrate honors declared norms per peer trust anchor for the norm publisher. Norms from untrusted publishers may be observed but not honored automatically; operator ceremony can grant trust anchor to specific publishers.

For public spaces without clear publisher, community-declared norms via commons apply. Federation reputation for community norms works via DISTRIBUTED-KNOWLEDGE-COMMONS.

## Substrate's own emission discipline in shared spaces

Beyond receiving-side compliance, substrate's own emissions in shared spaces matter. Every substrate transmission is CSI-legible to nearby sensors — including nearby sovereign substrates in Sensing-Enabled mode.

Per WIFI-SENSING-AND-RF-SURVEILLANCE, three emission modes exist: RF Quiet, Standard, Sensing-Enabled. In shared spaces, mode selection composes with declared space norms:

- Space norm declares RF Quiet expected → substrate enters RF Quiet on space entry, exits on space exit
- Space norm permits Standard → substrate maintains operator-declared mode
- Space norm permits Sensing-Enabled → substrate can activate sensing extensions per operator authorization

Substrate does not enter Sensing-Enabled mode automatically because a space permits it. Operator ceremony is required for the mode transition regardless.

### Waveform-layer discipline

Per the 802.11bf gap analysis: the substrate's own sensing signals in Sensing-Enabled mode are potentially adversarial-reading fodder. Substrate implements waveform-layer discipline (secure-LTF-inspired protected sounding waveforms) for its own sensing emissions where the underlying radio hardware supports it.

This does not prevent commodity WiFi traffic from being CSI-legible (physics cannot cooperate on that). It does prevent dedicated sensing sounding signals from making the substrate's own sensing activity into a broadcasting-of-sensable-material to adversaries. Where hardware supports, waveform protection is default-on for sensing emissions; where hardware does not support, substrate surfaces the limitation to operator.

## Kindred sovereigns in shared strangers spaces

Special case: when kindred sovereigns (per SOVEREIGN-KINSHIP-PRIMITIVES) are copresent in a shared space that also contains strangers, kinship-scope sharing continues but does not extend to strangers.

- Kindred sovereigns can share biometric findings under their granted scopes (still copresence-gated per kinship)
- Kindred sovereigns can activate `mutual_safety_check` or `household_presence` scopes
- Neither kindred sovereign's substrate shares stranger observations with the other
- Neither kindred sovereign's Regent narrates about specific strangers to their operator (anonymized presence only, per operator preference)
- Space norms apply to both kindred sovereigns equally; being kindred does not exempt from space-declared norms

If the kindred sovereigns are in a space where sensing is restricted, their kinship-scope biometric sharing pauses even though they'd normally have it authorized. Space norms take precedence over kinship-authorized scopes when the norm restricts the sensing modality itself.

## Regent's role in shared spaces

Regent's cognitive input plane treats shared-space observations at Tier 2-3 (contextual, advisory), not Tier 1. Shared-space context informs Regent's coordination decisions for operator without becoming primary attention target.

Regent's shared-space discipline:

- Narrate space-norm application to operator on entry/exit ("entering a space with restrictive sensing norms; adjusting emission mode")
- Narrate bystander-signal compliance events when operationally relevant
- Do NOT narrate specific strangers' observations to operator (only anonymized presence when relevant to coordination)
- Do NOT propose identifying strangers even under operator prompting (substrate invariant regardless of operator directive)
- Surface norm violations detected in the space (e.g., adversarial probing) to operator per HARDWARE-COMPROMISE-EVIDENCE discipline

Regent may propose emission-mode transitions per space norms; operator ceremony required for the transition. Standing corrections govern shared-space narration preferences per operator.

## Attack model

- **Attacker forges bystander preference beacon to disrupt legitimate sensing**: beacons are chain-signed by bystander's Genesis; forgery requires Genesis compromise. Replay attacks prevented by timestamp inclusion.
- **Attacker forges space norm to permit adversarial sensing**: norms are commons-hosted with publisher signatures; unknown publishers are not automatically trusted; commons reputation and peer trust anchor discipline manage.
- **Attacker deploys rogue AP in space to violate declared norms**: adversarial detection per HARDWARE-COMPROMISE-EVIDENCE catches. Space's declared norm being violated does not authorize substrate to counter-attack; substrate emits detection receipt, chain-visible norm violation propagates via commons.
- **Attacker uses public-space anonymity to conduct passive surveillance**: substrate can detect adversarial probing patterns; passive extraction that emits no detectable signal is the harder threat (per Piron's analysis) and requires broader civil-society response beyond substrate scope.
- **Attacker in same space as operator uses kinship-signal impersonation**: kinship declarations require mutual Genesis signatures; attacker cannot forge kinship with target without Genesis compromise. Cross-Regent narrations verify against chain integrity.
- **Attacker builds identification database from public-space substrate emissions**: substrate emits some ambient signal (Genesis-signed peer sync, coordination beacons); attacker collecting these could build identification database. Emission timing randomization reduces predictability; RF Quiet mode is available for high-threat contexts. Substrate's discipline does not close this attack entirely; operator physical security and disciplined mode selection are complementary.
- **Attacker attempts identification via cross-substrate patterns**: substrate does not share identification with peers under any scope. Attacker with access to multiple substrates cannot aggregate stranger identification because substrates don't identify strangers.

## Failure modes

- **Space norm publisher unknown, substrate defaults conservative**: unknown-space defaults may restrict operator's sensing more than intended. Standing correction can declare "in unknown spaces, permit Sensing-Enabled if my declared trigger patterns require it" (operator override with narrow scope).
- **Bystander signal received but substrate cannot verify signature**: signal ignored; sensing continues per space norm. Substrate chain-anchors the unverifiable signal event for potential retrospective review.
- **Multiple space norms in overlapping scope**: substrate composes to more-restrictive. Emits `substrate:space_norm_composed:<space_ids>` receipt showing the composition.
- **Norm publisher becomes adversarial**: operator revokes trust anchor for that publisher; substrate stops honoring their declared norms. Community reputation flow via commons.
- **Substrate cannot enter RF Quiet in space that requires it (hardware limitation)**: substrate declares limitation to operator; operator decides whether to remain in space with substrate active or deactivate substrate. Standing correction governs default preference.
- **Kindred sovereigns violate shared-space norms via their kinship sharing**: kinship-scope sharing pauses when the underlying sensing modality is restricted by space norm. Space norm is authoritative in the space; kinship is authoritative outside space-declared restrictions.
- **Bystander sovereignty gap**: non-sovereign bystanders cannot signal preferences via chain-anchored beacon. Substrate defaults to conservative behavior in ambiguous cases (unknown-space defaults; presence-only when possible); civil-society mechanisms handle the broader gap.

## Non-goals

- **Not a substitute for regulation**. Substrate discipline addresses what substrate does; regulation addresses what all sensing technologies do. Substrate composes with regulation, doesn't replace it.
- **Not universal compliance enforcement**. Substrate cannot force non-substrate devices (rogue APs, custom sensing hardware) to honor bystander signals. Substrate discipline covers substrate operators; broader civil society addresses the rest.
- **Not automatic identification even under operator request**. Identification of strangers is not offered as a primitive regardless of operator ceremony. If operator wants to identify someone, they engage them directly through human channels.
- **Not stranger relationship inference**. Substrate does not pattern-match repeated encounters into implicit relationships. Coordination-not-oversight (KEEL III.23) applies.
- **Not universal norm arbiter**. Substrate is norm-consumer, not norm-authority. Norms are declared by spaces and communities; substrate honors declared norms via commons trust.
- **Not solve for non-sovereign bystanders alone**. Non-sovereigns lack the signaling primitive; substrate defaults conservative but this gap requires broader mechanisms (regulation, physical shielding, cultural norms).

## Open positions

- **Beacon payload standardization**. Chain-signed beacon payloads need cross-substrate standard. Federation working spec? Reference implementation with commons publication?
- **Norm URI schema**. Commons-hosted norm declarations need canonical URI form. Federation standard.
- **Unknown-space defaults calibration**. What's the right conservative default when no space norm is declared? Presence-only + RF Quiet? Presence-only + Standard? Operator-tunable per standing correction.
- **Non-sovereign bystander advocacy**. Should substrate optionally-default to more-restrictive behavior in spaces where non-sovereign bystanders are likely present (public transit, public streets)? Trade-off: safety for non-sovereigns vs operator's coordination utility.
- **Kindred sovereigns co-declared spaces**. Two households sharing a vacation rental — can they collectively declare a temporary space norm? Trade-off: primitive expressiveness vs added complexity.
- **Beacon-detection cadence**. How often does substrate scan for bystander signals? Continuous vs periodic. Trade-off: compliance responsiveness vs substrate resource use.
- **Regulatory alignment**. GDPR, forthcoming regulations. Substrate's discipline should compose cleanly with regulation-required behaviors. Cross-jurisdiction default configuration.
- **Emission mode transitions during multi-space moves**. Operator moves through several spaces quickly (walk from apartment through lobby, transit, to office). Mode transitions cadence affects substrate stability.

## What composes from here

Immediate design work:

1. **Bystander preference beacon schema** — chain-signed payload standard
2. **Space norm declaration schema** — commons-hosted URI structure
3. **Substrate compliance protocol** — scanning, verification, application flow
4. **Waveform-layer discipline implementation** — secure-LTF-inspired sensing signal protection where hardware supports
5. **Regent shared-space narration policy** — what to surface, what to withhold

Near-term implementation:

1. Bystander beacon scanner in `crates/zp-server/src/shared_space/beacon/`
2. Space norm resolver (physical beacon + commons registry + defaults)
3. Emission mode transition manager per space norm
4. Compliance receipt emitters
5. Dashboard shared-space panel (currently-active norm, currently-active mode, compliance events)
6. CLI verbs: `zp shared_space status|norm|bystander|history`
7. Reference federation working spec for beacon and norm formats

## Framing note

Shared-space sensing etiquette extends the substrate's coordination-not-oversight discipline (KEEL III.23) to a specific class of contexts: physical spaces containing many sovereigns and non-sovereigns, where categorical review would be the default failure shape. The substrate's structural response is to make coordination-oriented sensing possible (operator's own presence detection, adversarial detection, safety check-ins under narrow scope) while structurally refusing the surveillance-oriented shape (stranger identification, stranger relationship graphs, retention of stranger-linked evidence).

The load-bearing insight: **in shared spaces, the substrate is a considerate sovereign, not a scanner.** Substrate operators are sovereigns who happen to be present alongside other sovereigns and non-sovereigns; their substrates behave as such. Bystander signaling is honored by construction. Space norms are honored by construction. Substrate's own emissions are disciplined per declared norms. Neither operator authorization nor extension declaration unlocks categorical review of strangers — that's a substrate invariant, not a configurable behavior.

Combined with the substrate's structural discipline across every trust boundary — actions, admissions, observations, cognition, extensions, hardware, emergency response, Genesis rotation, peer trust, build lifecycle, reproducibility, recovery UX, standing corrections, hardware compromise evidence, WiFi sensing, sovereign kinship, crisis response — shared-space etiquette completes the population-scale coordination envelope. What was implicit in traditional physical presence — "I'm in a space with others; I extend them ordinary consideration" — becomes structural in a substrate-adopting world: bystander signals are honored, space norms respected, own emissions disciplined, strangers not categorically observed. The substrate scales sovereignly, and every sovereign it supports operates as a considerate neighbor by construction.
