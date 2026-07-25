# Copresence Beacon Protocol

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), §II.15 (substrate boundary planes), §III.23 (coordination not oversight). Specifies the short-range chain-signed beacon protocol used by kinship copresence detection and shared-space bystander preference signaling. Layer B wire-format spec: what substrates emit and how they interpret received beacons. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md` (kinship copresence detection consumes this protocol), `SHARED-SPACE-SENSING-ETIQUETTE-2026-07.md` (bystander preference signaling consumes this protocol), `HARDWARE-COMPROMISE-EVIDENCE-2026-07.md` (adversarial beacon impersonation detection), `PEER-TRUST-ANCHOR-2026-07.md` (beacon verification against known peer identities).

## Framing

Multiple substrate primitives require short-range chain-signed signaling: substrates announce their presence to nearby kindred substrates (per SOVEREIGN-KINSHIP-PRIMITIVES copresence detection); sovereigns as bystanders declare their sensing preferences to nearby sensing-capable substrates (per SHARED-SPACE-SENSING-ETIQUETTE); substrates may declare local trust anchor updates or peer discovery signals over short-range channels. These use cases share the same underlying protocol infrastructure: short-range, chain-signed, replay-attack-resistant, low-power, verifiable by receivers without pre-existing session.

This spec consolidates the beacon protocol into a single canonical Layer B specification. Rather than each consuming spec redefining its own beacon format, all short-range signaling shares the substrate's canonical copresence beacon protocol.

Three properties frame the protocol:

1. **Chain-signed by construction.** Every beacon carries the emitting sovereign's Genesis-derived signature over the beacon content plus a fresh timestamp. Receivers verify signatures before acting on beacon content. Forgery requires Genesis compromise.
2. **Purpose-typed payloads over shared envelope.** Same envelope format across use cases; payload type field distinguishes kinship-copresence from bystander-preference from other beacon classes. Extensible for future beacon types without breaking existing consumers.
3. **Short-range by design.** Physical layer selection (BLE, UWB, optical) constrains reach to physical proximity. This is a protocol invariant — beacons are not designed to travel beyond immediate physical vicinity. Amplifiers or relays are attack surface, not feature.

## Physical layer

Substrate emits beacons over one or more short-range radio channels per Substrate Form capability and operator preference:

- **Bluetooth Low Energy (BLE)**: ~10-30 meter range at standard power; ubiquitous chipset support; primary default for most Substrate Forms. Uses BLE advertising channels (37, 38, 39) with substrate-standard service UUID.
- **Ultra-Wideband (UWB)**: 1-100 meter range depending on protocol; higher-precision proximity when many beacons present; distance-bounding capability resistant to some relay attacks. Emerging support in premium consumer devices.
- **Optical (VLC / IR)**: line-of-sight, few meters. High-visibility declaration option. Useful when overt signaling is preferred over ambient radio broadcast.
- **NFC**: sub-10cm range, deliberate proximity gesture (touch phones together, tap substrate). Used for explicit high-consent operations like initial kinship declaration.

Substrate typically emits over multiple channels simultaneously; receiving substrates listen on all channels their hardware supports. Beacon envelope is channel-independent; physical layer is transport.

## Beacon envelope

Every beacon carries the same envelope structure regardless of purpose:

```
Beacon Envelope {
  version: u16                   // protocol version (currently 1)
  beacon_type: u16               // payload type discriminator
  emitter_pubkey: [32]           // emitter's Genesis-derived public key
  timestamp_ms: u64              // emitter's timestamp (Unix epoch ms)
  nonce: [16]                    // random per-beacon nonce (replay resistance)
  payload_length: u16            // length of payload in bytes
  payload: [payload_length]      // type-specific payload
  signature: [64]                // Ed25519 signature over envelope bytes
                                 //   preceding this field
}
```

Envelope is compact by design — BLE advertising has limited payload capacity (~31 bytes for legacy, ~255 bytes for extended advertising). Extended-advertising format is default; legacy format is used only in constrained interoperability contexts.

For payloads exceeding BLE extended-advertising capacity, beacons use fragmentation: multiple beacons emitted in sequence with fragment-id fields; receivers reassemble. Fragmentation is envelope-transparent — signature covers the complete reassembled envelope.

## Beacon types

Initial canonical beacon type set:

### Type 1 — Kinship copresence announcement

Emitted continuously (per operator-configured cadence) by substrates with active kinship declarations. Announces "sovereign X is here" to nearby substrates that may have kinship with X.

Payload:
```
KinshipCopresence {
  scope_hint: u16           // which kinship scope classes are active
  privacy_mode: u16         // full announcement / kinship-only / dark
}
```

`scope_hint`: bitfield indicating which sharing scopes are potentially active for kindred sovereigns detecting this beacon. Kindred receiver checks their own kinship declaration to determine what's actually authorized.

`privacy_mode`:
- `full`: any receiver can see the beacon (used in trusted contexts like home)
- `kinship_only`: beacon encrypted such that only sovereigns with active kinship can decrypt (uses HPKE against known kindred pubkeys; requires kindred pubkey pre-registration)
- `dark`: beacon not emitted (substrate does not announce presence)

Cadence: typically every 1-5 seconds when active. Operator-configurable.

### Type 2 — Bystander preference declaration

Emitted by sovereigns acting as bystanders (per SHARED-SPACE-SENSING-ETIQUETTE) declaring their sensing preferences to nearby sensing-capable substrates.

Payload:
```
BystanderPreference {
  preference_class: u16     // no_sense / presence_only / default
  scope_hint: u16           // which sensing classes this applies to
  duration_ms: u32          // validity window (bystander may be in transit)
}
```

`preference_class`:
- `no_sense`: bystander prefers not to be sensed by any nearby substrate
- `presence_only`: bystander accepts anonymized presence detection, refuses biometric/activity
- `default`: no explicit preference (substrate uses space norms or defaults)

Cadence: typically every 1-5 seconds when active. Operator can also emit single-shot beacons for specific encounters.

### Type 3 — Peer discovery announcement

Emitted when substrate is looking for peer connections in the local physical space (e.g., first-time meeting between two sovereigns who want to establish kinship). Enables ceremony-in-person initiation without prior remote pairing.

Payload:
```
PeerDiscoveryAnnouncement {
  discovery_intent: u16     // seeking_kinship / seeking_care_contact / etc.
  contact_hint: [variable]  // optional hint about how to establish next-step contact
}
```

Discovery beacons enable spontaneous peer establishment ceremonies in physical proximity. Both parties opt-in via UX flow; receipt exchange proceeds via secure channel established from beacon-shared pubkeys.

### Type 4 — Space norm advertisement

Emitted by physical spaces to advertise their sensing norms (per SHARED-SPACE-SENSING-ETIQUETTE). Emitter is the space's operator (venue owner, community steward) or their delegated authority.

Payload:
```
SpaceNormAdvertisement {
  norm_uri_hash: [32]       // hash of commons-hosted norm document
  norm_publisher_pubkey: [32]  // publisher's Genesis pubkey (for trust anchor check)
  scope_meters: u16         // physical scope this norm applies within
}
```

Substrates observing space norm advertisements query commons registry for the actual norm document by URI hash; verify publisher; apply if publisher is trusted.

### Type 5 — Substrate liveness heartbeat (short-range)

Optional emission for substrates that maintain short-range liveness signals within a household or trusted physical space. Not the primary heartbeat mechanism (which is chain-anchored per OPERATOR-DEATH-AND-LEGACY), but a physical-proximity signal for local coordination.

Payload:
```
LivenessHeartbeat {
  household_id: [32]        // if operator is member of household collective
  status: u16               // active / rest / away
}
```

Substrate types 6+ reserved for future extensions. Registry via federation working spec.

## Verification

Receivers verify received beacons before acting:

1. **Signature check**: Ed25519 verification against emitter pubkey using envelope bytes preceding signature field. Failed verification → discard beacon; optionally log as `beacon:verification_failed:<beacon_hash>` for forensic review.
2. **Timestamp freshness**: emitter timestamp within acceptable skew (default: within 10 seconds of receiver's clock). Prevents replay of old signed beacons.
3. **Nonce uniqueness**: receiver maintains short-term cache of recent nonce values per emitter; duplicate nonce indicates replay attempt.
4. **Emitter trust**: emitter pubkey checked against receiver's relevant trust anchor (kinship declaration for kinship beacons, peer trust anchor for space norms, etc.).
5. **Payload validation**: payload structure valid for declared beacon type.

Verified beacons are then acted upon per receiving substrate's discipline (kinship copresence activation, bystander preference honoring, etc.).

## Replay attack resistance

Beacons are broadcast; attackers can capture and re-emit. Replay resistance via:

- **Timestamp freshness window**: beacons more than 10 seconds old rejected by default
- **Per-emitter nonce cache**: duplicate nonces from same emitter within cache window rejected
- **Chain-anchored beacon receipt sampling**: substrates optionally chain-anchor a sampling of received beacons for retrospective anomaly detection

Attacker replaying beacons within freshness window can create false transient signals but cannot sustain false impressions long. Cognitive Self-Observer flags anomalous beacon patterns for operator investigation.

## Chain-anchoring beacon events

Substrates chain-anchor beacon-related events per their discipline:

- Kinship copresence detection: `kinship:copresence_detected:<kinship_id>:<detection_id>` receipt when kindred beacon verified
- Bystander preference compliance: `substrate:bystander_signal_honored:<beacon_id>` receipt when bystander preference applied
- Space norm application: `substrate:space_norm_observed:<space_id>:<norm_id>` receipt when space norm entered
- Verification failures: `beacon:verification_failed:<beacon_hash>` receipts for forensic review
- Anomalous beacon patterns: `beacon:anomaly_detected:<pattern_id>` receipts feeding HARDWARE-COMPROMISE-EVIDENCE community signature catalog

Beacon content itself is not chain-anchored verbatim; only the derived substrate events.

## Emission discipline

Substrate emits beacons per operator preferences and per-context discipline:

- **RF Quiet mode** (per WIFI-SENSING-AND-RF-SURVEILLANCE): substrate suppresses beacon emissions except emergency-critical types
- **Standard mode**: substrate emits per operator preference across configured beacon types
- **Sensing-Enabled mode**: substrate emits at cadence supporting active sensing operations

Space norms may require specific emission behavior (e.g., "no discovery beacons in this space"); substrate composes per space norm on entry.

Beacon emissions are chain-visible when operator has authorized emission mode transition ceremonies. Substrate does not silently change emission behavior.

## Attack model

- **Attacker forges kindred sovereign's kinship copresence beacon**: signature verification against known Genesis; forgery requires Genesis compromise. Nonce/timestamp prevent replay.
- **Attacker relays legitimate beacons from distant location to make sovereign appear present locally**: UWB with distance-bounding resists this. BLE without distance-bounding is vulnerable; substrate cross-checks with other signals (multi-channel confirmation, movement patterns) before critical decisions.
- **Attacker floods space with fake beacons for DoS**: rate limits on beacon processing; anomalous beacon volume triggers HARDWARE-COMPROMISE-EVIDENCE Class B captures.
- **Attacker captures and replays bystander preference beacons to override real bystanders**: freshness window (10 seconds) limits attack window. Chain-anchored sampling detects sustained replay patterns.
- **Attacker uses space norm advertisement to induce restrictive substrate behavior**: substrate verifies publisher against trust anchor; unknown publishers not honored automatically. Operator can inspect current norms via dashboard.
- **Attacker uses discovery beacons to enumerate nearby sovereigns**: discovery beacons are opt-in per operator (not emitted continuously); privacy-mode `kinship_only` encrypts to known kindred; general discovery is only emitted during active peer-establishment ceremonies.
- **Attacker exploits beacon fragmentation to inject partial payloads**: signature is over complete reassembled envelope; partial payloads fail signature verification.
- **Attacker uses long-range receiver to observe beacons intended for short-range only**: physical layer selection limits reach but cannot guarantee attacker doesn't have specialized receivers. Substrate's operational assumption is that beacons may be observed by anyone in receiving range; sensitive content is not carried in unencrypted beacons.

## Failure modes

- **Legitimate kindred beacon fails verification due to clock skew**: timestamp acceptance window may be too narrow. Substrate can propose relaxed window with operator authorization; substrate does not silently accept old beacons.
- **BLE advertising channel congestion in dense spaces**: high-density substrate deployment saturates BLE. UWB or optical fallback; substrate emission cadence may reduce.
- **Beacon fragmentation failure**: fragmented beacon partially received; reassembly fails. Substrate emits fresh full beacon on next cadence; failure receipt for forensic.
- **Payload version mismatch**: emitter and receiver on different protocol versions. Envelope version field enables graceful degradation; receiver treats unknown types as no-op.
- **Bystander preference beacon received but sensing extension has already emitted**: preference honoring is preemptive; late arrival compliance requires substrate to abort in-progress sensing. Some operations may not be abortable mid-cycle; substrate discloses limitation.
- **Space norm advertisement from adversarial publisher**: substrate ignores unknown publishers by default; operator can grant trust to specific publishers via ceremony.

## Non-goals

- **Not a substitute for chain-anchored ceremony**. Beacons are transient signals; chain receipts are truth. Beacons trigger substrate behavior but do not themselves establish trust anchors, kinships, or delegations.
- **Not universal wireless protocol**. Substrate does not attempt to displace existing wireless standards (WiFi, Bluetooth, cellular). Substrate uses these standards as transport for its own beacon envelope.
- **Not attacker-proof against physical proximity**. Attacker with same physical access as legitimate sovereign can potentially participate in short-range signaling. Substrate discipline complements physical access controls, doesn't replace them.
- **Not full-anonymity beacon protocol**. Beacons carry emitter pubkey (chain identity). For anonymity contexts, substrate uses different mechanisms (ephemeral pubkeys for specific ceremonies, no-emission mode entirely).
- **Not directional signaling protocol**. Beacon envelope does not carry direction/bearing information beyond what physical layer provides. Directional applications compose separately.

## Open positions

- **BLE 6 / Wi-Fi Aware integration**: emerging short-range standards may provide better substrate-fit; federation working spec for standard adoption.
- **Federation-standard service UUIDs**: BLE service UUID for substrate beacons needs canonical allocation; SIG membership vs local prefix.
- **UWB distance-bounding integration**: standardized UWB profiles for substrate distance-bounding; cross-vendor compatibility.
- **Optical beacon standardization**: which VLC / IR protocols; interoperability with camera-glasses etiquette per SHARED-SPACE-SENSING-ETIQUETTE.
- **Beacon anonymization for sensitive contexts**: ephemeral pubkey ceremonies for specific short-lived interactions (e.g., mutual introduction in a bar); protocol design.
- **Compressed payload formats**: extremely tight BLE legacy advertising (31 bytes) constrains payload. Compressed encodings for specific beacon types.
- **Beacon rate limiting per space norm**: some spaces may restrict beacon emission frequency (hospitals, sensitive facilities). Space norm schema for cadence restrictions.
- **Multi-fleet operator beacons**: operator with multiple devices in fleet — do all devices emit same beacon, or per-device beacons? Trade-off: presence redundancy vs beacon spam.

## What composes from here

Immediate design work:

1. **Envelope byte-format specification** — canonical wire format
2. **Beacon type registry** — federation working spec for type allocations
3. **BLE advertising integration** — service UUID, advertising modes
4. **UWB integration** — profile selection, distance-bounding
5. **Physical layer selection algorithm** — how substrate chooses which channels to emit on
6. **Verification pipeline reference implementation**

Near-term implementation:

1. Beacon emitter in `crates/zp-server/src/beacon/emit/`
2. Beacon receiver in `crates/zp-server/src/beacon/recv/`
3. Envelope encoding/decoding utilities
4. Signature and nonce verification pipeline
5. Physical layer bindings (bluer for BLE on Linux; equivalent for other Forms)
6. Integration with KINSHIP-PRIMITIVES for copresence detection
7. Integration with SHARED-SPACE-SENSING-ETIQUETTE for bystander preference
8. Dashboard beacon panel (active emissions, received beacons, verification failures)
9. CLI verbs: `zp beacon emit|recv|history|status`

## Framing note

Copresence beacon protocol consolidates short-range chain-signed signaling into a single canonical Layer B specification. Same principle as chain-anchored discipline elsewhere — Genesis signatures gate trust, chain records events, verification precedes action.

The load-bearing insight: **short-range signaling shares infrastructure across use cases.** Kinship copresence, bystander preference, peer discovery, space norm advertisement, liveness heartbeat — all consume the same envelope, same verification pipeline, same physical layer. Consolidation into a single protocol prevents drift between use cases and enables one implementation to serve all.

Combined with the substrate's structural discipline across every trust boundary, copresence beacon protocol provides the wire-format foundation for short-range coordination. What consuming specs (KINSHIP-PRIMITIVES, SHARED-SPACE-SENSING-ETIQUETTE) reference as "chain-signed short-range beacon" is now a concrete Layer B protocol: envelope structure, type registry, verification pipeline, physical layer integration. Sovereignty is preserved because every beacon is Genesis-signed by the emitter; safety is preserved because verification precedes action; continuity is preserved because chain-anchored events derived from beacons integrate with the substrate's broader chain discipline.
