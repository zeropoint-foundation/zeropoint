# Transport Abstraction and Constrained Networks

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), §III.20 (forward-only recovery), Part VII (Peer-Verification Contract), Part XIV (Substrate Realization). Specifies the substrate's transport-layer discipline: how chain-anchored primitives compose over any message-oriented transport, from high-bandwidth TCP/HTTP to low-bandwidth constrained mesh (Reticulum, LoRa, packet radio). Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `COPRESENCE-BEACON-PROTOCOL-2026-07.md` (short-range beacon transport as one specific case), `DISCOVERY-AND-BOOTSTRAP-2026-07.md` (discovery layers per transport), `PEER-TRUST-ANCHOR-2026-07.md` (peer trust independent of transport), `SUBSTRATE-FORM-2026-07.md` (transport capabilities vary by Form), `REPRODUCIBILITY-CEREMONY-2026-07.md` (chain evidence portable across transports), `FREENET-TRANSPORT-CONFORMANCE-2026-07.md` (a public overlay conformed against this document's message transport contract; added 2026-07-27), `DECENTRALIZED-TRANSPORT-OPPORTUNITY-MAPPING-2026-07.md` (the lens that produced it).

## Framing

Substrate design has implicitly assumed TCP/HTTP-ish transport throughout the corpus. This is a real gap. Substrate needs to work over any message-oriented transport where two nodes can exchange chain-anchored receipts — including transports with dramatically different capacity: TCP/HTTP over broadband (megabytes per second, reliable delivery), WebSocket over cellular (variable capacity, session-oriented), Reticulum RNS over mesh (low-bandwidth, high-latency, opportunistic), LoRa (50-250 byte packets, minutes-to-hours latency, extreme intermittency), packet radio (packet-oriented, unreliable, region-specific), and short-range channels (BLE, UWB, optical — bounded reach, high-bandwidth within reach).

Making transport explicit is not optional. Substrates in mesh-network scenarios, disaster-response contexts, off-grid deployments, and Sovereign Form Pi 5 deployments in constrained-connectivity regions all depend on transport composability that our current corpus assumes without specifying. This spec closes that gap: transport is an abstraction layer, chain primitives are transport-agnostic by construction, and adaptive behavior lets substrate operate gracefully across the full range from broadband to LoRa.

Three properties frame the discipline:

1. **Chain primitives are transport-agnostic.** Signatures verify identically over any transport. Hash-linkage integrity holds regardless of delivery path. Content-addressable receipts deduplicate across multi-path delivery. What arrives at any peer via any transport is verifiable per the same Genesis-derived signing discipline.
2. **Wire format degrades gracefully to transport capacity.** JSON debug format for observability + CBOR-style binary encoding for compaction + optional fragment-and-reassemble discipline for extreme constraint. All encodings hash to the same canonical content ID; receipt integrity survives format conversion.
3. **Store-and-forward is primary, not fallback.** Chain receipts land in local chain regardless of when peer sync happens. Peer sync is opportunistic — happens when transport is available, resumes gracefully when transport recovers. Substrate makes progress with offline periods, delayed delivery, and asymmetric connectivity.

## The transport abstraction

Substrate defines a **message transport contract** that any transport implementation satisfies. Above the contract, chain primitives are transport-agnostic. Below the contract, transport-specific adapters handle wire-level details.

### The message transport contract

Any transport that satisfies this contract can carry substrate primitives:

- **Message boundaries preserved.** A receipt sent as one message arrives as one message (or fragmented and reassembled with fidelity). No transport-imposed reframing.
- **Content integrity verifiable.** Recipient can verify the message was not modified in transit via signature verification. Transport does not need to be secure; substrate signature discipline handles integrity.
- **Best-effort delivery acceptable.** Transport is not required to guarantee delivery. Substrate handles retry, deduplication, and store-and-forward at the substrate layer.
- **Message-oriented, not stream-oriented.** Substrate operates on discrete receipts, not byte streams. Stream transports (TCP) are wrapped to expose message semantics.
- **Bidirectional (or optional-reply).** Transport supports peer replying to sender. Broadcast-only or one-way transports are supported but limit substrate capability at those transports.

Transports satisfying this contract get first-class substrate composability. Adapters exist for:

- **TCP/HTTP** — baseline. JSON-over-HTTPS for peer sync, dashboard, tools.
- **WebSocket** — bidirectional streaming for live updates within a substrate session.
- **Reticulum RNS + LXMF** — mesh transport with propagation nodes. Store-and-forward native. Peer identity abstracted over RNS destination.
- **Public overlay networks (Freenet)** — content-addressed state over a small-world routed peer network with no servers; peers relay opaque signed payloads they cannot read. Store-and-forward native, and the propagation-node discipline below applies unchanged — depend on an overlay peer for availability, never for integrity. Latency is routed-and-eventual rather than link-bounded, so it sits closer to the medium-bandwidth mode than to TCP. Targeted 2026-07-27 per `FREENET-TRANSPORT-CONFORMANCE-2026-07.md`: one adapter among several, feature-gated, never the only path. Distinct from the other entries in one respect worth naming — the medium is reachable by anyone rather than by peers the operator attached, which makes inbound authentication load-bearing in a way a private mesh lets it not be.
- **LoRa (LoRaWAN or direct)** — constrained payload (50-250 bytes region-dependent), high latency, high intermittency. Fragmentation required for most receipts.
- **Packet radio (AX.25, FT8, others)** — amateur-radio-friendly, region-dependent regulatory constraints, low-bandwidth.
- **BLE / UWB** — short-range, high-bandwidth-within-reach. Per COPRESENCE-BEACON-PROTOCOL.
- **Optical (VLC, IR)** — line-of-sight, sub-second latency, low-bandwidth.
- **Sneakernet** — physical media transfer (USB drive, QR codes). Extreme intermittency but valid transport.

## Wire format tiers

Substrate emits and receives chain receipts in three wire format tiers, each hashing to the same canonical content ID (per hash-linkage discipline):

### Tier A — JSON debug format

Human-readable JSON with full field names. Used for observability, debugging, dashboard display, tool invocation, and any context where legibility matters more than compactness. Baseline for TCP/HTTP transport.

Example: `{"type":"kinship:copresence_detected","kinship_id":"...","detection_id":"...","timestamp":"2026-07-11T20:04:00Z","signature":"..."}`

### Tier B — CBOR canonical binary

RFC 8949 CBOR with canonical encoding rules. Approximately 30-50% smaller than JSON for the same content. Field name interning via CBOR tag registry. Fixed-width integer encoding. Used for peer sync over bandwidth-constrained transports and for content-addressable receipt hashing (canonical CBOR hashes are deterministic across implementations).

The canonical hash of a receipt is computed over its Tier B CBOR encoding regardless of what wire format the receipt was transmitted in. This means the same receipt sent over JSON, CBOR, or fragmented CBOR always resolves to the same content ID; deduplication happens at the ID level.

### Tier C — Fragmented CBOR

For transports with payload limits below single-receipt size (LoRa's 50-250 bytes, packet radio's ~200 bytes typical), substrate fragments Tier B CBOR into transport-sized chunks with:

- Fragment header (12 bytes): content ID hash prefix + fragment index + total fragment count
- Fragment payload (transport-max minus header size)
- Per-fragment signature-of-header (compact) for tampering detection

Recipient reassembles fragments by content ID prefix, verifies fragment integrity, decodes CBOR, verifies full receipt signature. Missing fragments trigger targeted re-request over the same transport if bidirectional; otherwise waits for opportunistic retry.

## Store-and-forward discipline

Chain-anchored substrate operations do not block on peer sync. Every receipt lands in local chain immediately regardless of transport availability. Peer sync is opportunistic:

- **Emit locally always.** Substrate emits receipts to local chain immediately. Chain integrity, hash-linkage, and signature discipline are preserved regardless of downstream delivery.
- **Queue for peer delivery.** Receipts intended for peer distribution accumulate in per-peer outbound queues. Queue persists across substrate restart.
- **Deliver opportunistically.** When transport to peer becomes available, drain outbound queue with appropriate batching for transport capacity. Batch small for LoRa, stream for TCP.
- **Deduplicate at content ID.** Multi-path delivery (peer receives same receipt via TCP and via LoRa relay) deduplicates at content-ID level. Chain integrity holds regardless of delivery path.
- **Propagation nodes** (per Reticulum LXMF discipline): substrate can rely on third-party store-and-forward nodes for peers that are not currently reachable. Propagation nodes hold receipts until recipient becomes reachable. Substrate does not depend on propagation node integrity for content integrity (signatures verify end-to-end) but does depend on availability for eventual delivery.

Store-and-forward composes with `store-and-forward is primary` design principle (KEEL Principle 5). Substrate's chain survives arbitrary transport outages; peer sync catches up when transport returns.

## Adaptive behavior across transport capacity

Substrate detects transport capacity and adjusts operational patterns accordingly:

### High-bandwidth mode (TCP/HTTP over broadband)

- Full JSON wire format for legibility
- Real-time peer sync via WebSocket
- Continuous chain-watcher event streaming
- Dashboard live updates
- Rich cognitive input plane assembly per cycle
- Extension marketplaces browsable in real-time

### Medium-bandwidth mode (cellular, moderate mesh)

- CBOR wire format for peer sync
- Periodic peer sync (minutes-scale intervals)
- Chain-watcher events batched
- Dashboard updates on demand
- Cognitive input plane assembly at declared cadence
- Extension access via cached catalog + on-demand pull

### Low-bandwidth mode (LoRa, packet radio)

- Fragmented CBOR wire format
- Peer sync at hours-scale intervals
- Only critical chain-watcher events transmitted (emergency signals, care sovereign activations)
- Dashboard operates offline; sync when transport allows
- Cognitive input plane operates on cached state
- Extension access disabled; existing extensions operate locally

### Off-grid mode (sneakernet, delayed sync)

- Substrate operates fully locally
- Chain-anchored receipts accumulate for eventual sync
- Peer sync via physical media transfer or delayed connection window
- Cognitive input plane uses last-known peer state
- Chain integrity preserved; substrate provides value at N=1 (single sovereign)

Substrate detects mode via transport capacity measurement and operator preference. Mode transitions are chain-anchored via `substrate:transport_mode:transition:<mode>` receipts so post-hoc analysis can see operational context.

## Content addressing and multi-path delivery

Chain receipts are content-addressable via canonical CBOR hash. Content addressing enables:

- **Multi-path delivery.** Same receipt can arrive via multiple transport paths (TCP from origin, LoRa relay from mesh peer, propagation node from third party). Recipient deduplicates at content ID; chain integrity holds regardless of delivery path.
- **Verification independence.** Recipient can verify signature and hash-linkage without knowing which transport delivered the receipt. Transport identity is metadata, not part of receipt integrity.
- **Redundant peer sync.** Substrate can offer peer sync via multiple transports concurrently; recipient sees consistent receipt regardless of which arrives first.
- **Post-hoc reconstruction.** If a receipt is discovered via one transport that was thought lost via another, integrity verification confirms the receipt is authentic regardless of delivery history.

Content addressing also enables **relay networks** — third-party substrates that carry receipts on behalf of others without themselves being party to the content. Relay substrates verify integrity (signatures valid, hash-linkage correct) but do not need trust anchor grants to carry.

## Fragmentation discipline for extreme constraint

For transports with payload limits below single-receipt size, fragmentation follows a specific discipline:

- **Content-ID-prefix reassembly.** Fragments carry the first 8 bytes of the content ID hash. Recipient collects fragments matching same prefix; reassembles when total-fragment-count matches received-fragment-count.
- **Per-fragment integrity.** Each fragment carries a compact signature over its header preventing tampering with fragment metadata (index reordering attacks).
- **Missing fragment recovery.** Recipient tracks received fragments; can request specific missing fragments over bidirectional transport. Over broadcast-only transport (some LoRa modes), waits for opportunistic retransmission.
- **Reassembly timeout.** Partial reassembly buffers time out after operator-declared window (default: 1 hour for LoRa, 15 minutes for packet radio). Timed-out fragments discarded; sender retries on next opportunity.
- **Order-independence.** Fragments can arrive in any order. Reassembly does not require sequential delivery.

Fragmentation is transport-adapter concern. Substrate above the transport contract doesn't know about fragmentation. Chain integrity holds at receipt granularity regardless of below-transport fragmentation activity.

## Composition with existing specs

- **COPRESENCE-BEACON-PROTOCOL-2026-07.md**: short-range beacon transport (BLE, UWB, optical) is one specific transport implementation. Beacon envelope + payload types are the substrate primitives; short-range physical layer is one transport adapter satisfying the message transport contract.
- **DISCOVERY-AND-BOOTSTRAP-2026-07.md**: five discovery layers each operate over different transport mixes. Public directory listings via TCP/HTTP; seed nodes via TCP/HTTP; vouching receipts via any transport; rendezvous signals via short-range or commons; direct address exchange via any channel.
- **PEER-TRUST-ANCHOR-2026-07.md**: peer trust is per-peer per-surface, independent of which transport peer sync uses. Same peer trusted at same surface regardless of connectivity mode.
- **SUBSTRATE-FORM-2026-07.md**: Substrate Forms have different transport capabilities. Sovereign Form on Pi 5 with radio HAT can support Reticulum + LoRa + WiFi + Ethernet. Companion Form on macOS may be limited to TCP/HTTP. Per-Form transport capability declaration.
- **REPRODUCIBILITY-CEREMONY-2026-07.md**: chain evidence is portable across transports. Reproducibility ceremony works over any transport that satisfies the contract; substrate operations reproducible regardless of delivery path.
- **FREENET-TRANSPORT-CONFORMANCE-2026-07.md**: a public overlay conformed against the message transport contract above. Lands in `zp-mesh` behind the existing `DiscoveryBackend` trait rather than as a new abstraction. Its m0 is gated behind three prerequisites owed to the current mesh regardless of any new transport — wiring `DiscoveryManager` into a running binary, closing the inbound-authentication gap, and bounding the intake path. Note the dependency in the other direction: the contract accepts best-effort delivery on the condition that *"Substrate handles retry, deduplication, and store-and-forward at the substrate layer"*, and that layer is near-term implementation item 8 below, unbuilt. A store-and-forward medium makes its absence visible immediately where TCP on a LAN hides it.
- **CIRCUIT-BREAKER-2026-07.md**: transport degradation is not itself a circuit-breaker event; substrate adapts to lower-capacity modes gracefully. Sustained inability to sync with critical peers may escalate per operator preference.

## Attack model

- **Attacker exploits transport-specific vulnerabilities**: substrate integrity holds at receipt-signature level; transport-layer attacks (routing manipulation, denial of service) cannot forge receipts. Attacker can delay or drop but not fabricate.
- **Attacker floods low-bandwidth transport to prevent legitimate sync**: rate limits per transport adapter; store-and-forward preserves receipts for delivery when transport recovers. Sustained denial requires operator response (transport migration, peer route reconfiguration).
- **Attacker exploits fragment reassembly**: per-fragment integrity signatures prevent header manipulation; reassembly timeout prevents unbounded memory consumption; content ID verification catches manipulation at receipt level.
- **Attacker exploits multi-path delivery to cause receipt confusion**: content addressing enables deduplication; substrate sees consistent receipt regardless of arrival path. Any manipulation attempted mid-path fails signature verification.
- **Attacker compromises propagation nodes to censor**: substrate does not depend on propagation nodes for content integrity; alternate propagation nodes route around censorship; sustained propagation-node censorship requires operator response (route reconfiguration, alternate transport activation).
- **Attacker downgrades substrate to lower-bandwidth mode to reduce visibility**: transport mode transitions are chain-anchored so operator sees the transition; abnormal-frequency mode transitions are pattern-detectable.

## Failure modes

- **Transport becomes unavailable mid-sync**: outbound queue preserves pending receipts; sync resumes when transport recovers. Chain integrity unaffected.
- **Fragment reassembly incomplete**: timeout discards fragments; sender retries. If sender doesn't retry (offline extended period), receipt eventually delivered on next opportunity.
- **Cross-transport time skew**: receipts arriving via slow transport with old timestamps may appear out of order. Chain-integrity discipline handles: receipts land in chain by receipt-timestamp, not by arrival-timestamp; hash-linkage handles ordering.
- **Adaptive mode transition disrupts operations**: operator UX surfaces mode transitions; substrate operations pause gracefully during transition (batched retry, delayed non-urgent operations).
- **Peer available only over degraded transport for extended period**: substrate uses lower-tier operations for that peer; sync catches up when better transport returns. No permanent state divergence.
- **Content addressing collision**: cryptographic hash collision is effectively impossible with current primitives; substrate does not defend against 2^128 collision scenarios.

## Non-goals

- **Not universal transport support**. Substrate supports message-oriented transports that satisfy the contract. Byte-stream-only transports (SCTP without message boundaries), synchronous request-response-only transports (some HTTP-only frameworks) require adapter shimming.
- **Not real-time delivery guarantees**. Substrate is best-effort; time-critical operations must have their own synchronization discipline outside substrate.
- **Not censorship resistance at routing layer**. Substrate uses whatever routing infrastructure the transport provides; routing-layer censorship (ISP blocking, IP-level blackholing) is a transport concern, not substrate concern.
- **Not automatic transport migration**. Operator ceremony configures transport preferences; substrate does not autonomously switch transports without operator authorization.
- **Not sync-blocking substrate operation**. Substrate never waits for peer sync to complete before making local progress; all chain-anchored operations succeed locally regardless of transport state.

## Open positions

- **CBOR schema formalization**. Canonical CBOR encoding rules for all receipt types; deterministic hashing verified across implementations.
- **Fragment header standard**. Federation working spec for cross-substrate fragment format.
- **Adaptive mode calibration**. Thresholds for high/medium/low/off-grid mode transitions; operator-tunable, empirical-program-informed.
- **Propagation node registry**. Federated registry of propagation nodes for Reticulum/LXMF composition; reputation flow via commons.
- **Sneakernet ceremony**. Formal ceremony for physical-media chain transfer (USB drives, QR codes for critical receipts); integrity verification post-transfer.
- **Multi-transport routing**. Substrate operator has multiple transports available; policy for which transport to prefer for which peer / which class of receipt.
- **Radio regulatory compliance**. LoRa and packet radio have region-specific regulatory constraints (frequency, power, duty cycle). Substrate must not violate; per-jurisdiction transport configuration.
- **Battery-power discipline**. Constrained-transport deployments often battery-powered; transmit-power optimization per receipt priority.

## What composes from here

Immediate design work:

1. **Message transport contract spec** — formal interface definition for transport adapters
2. **CBOR canonical encoding spec** — deterministic hashing rules across implementations
3. **Fragment header schema** — federation working spec for cross-substrate fragmentation
4. **Adaptive mode transition ceremony receipts** — chain-anchored operational mode changes
5. **Multi-transport routing policy schema** — operator-declarable transport preferences

Near-term implementation:

1. **Transport abstraction layer** in `crates/zp-transport/src/`
2. **CBOR encoder/decoder** with canonical hashing
3. **TCP/HTTP adapter** (baseline; already implicit in current substrate)
4. **WebSocket adapter** for live sync
5. **Reticulum RNS adapter** with LXMF composition
6. **LoRa adapter** (LoRaWAN-mode + direct-mode)
7. **Fragmentation runtime** with reassembly buffer management
8. **Store-and-forward outbound queue** with persistence across substrate restart
9. **Adaptive mode manager** with capacity detection and transition ceremony emission
10. **CLI verbs**: `zp transport list`, `zp transport mode set|get`, `zp transport queue status`, `zp transport peer route`
11. **Public overlay adapter** (Freenet) — `DiscoveryBackend` first, `Interface` second; feature-gated, off by default. Sequenced after items 1 and 8, and after the inbound-authentication work named in `FREENET-TRANSPORT-CONFORMANCE-2026-07.md`.

## Framing note

Transport abstraction makes explicit what the substrate corpus has been implying: chain-anchored primitives operate over any message-oriented transport, from broadband TCP to constrained LoRa. Same principle as chain-anchored discipline elsewhere: transport-agnostic operations, store-and-forward primary, chain integrity preserved regardless of delivery path.

The load-bearing insight: **substrate is transport-agnostic by construction; wire format degrades gracefully to transport capacity; store-and-forward is primary rather than fallback.** Chain receipts land locally always; peer sync happens opportunistically. What arrives at any peer via any transport is verifiable per the same signature discipline. Substrate provides value at every transport tier — high-bandwidth broadband, moderate cellular, constrained mesh, off-grid sneakernet — without redesign.

Combined with the substrate's structural discipline across every trust boundary, transport abstraction closes the connectivity-envelope gap. What was previously implicit — that the substrate probably works over Reticulum or LoRa — becomes structural: message transport contract defined, wire format tiers spec'd, adaptive mode calibrated, store-and-forward primary, fragmentation discipline for extreme constraint. Sovereignty is preserved because operator declares transport preferences and authorizes transport migration; safety is preserved because chain integrity holds regardless of delivery path; continuity is preserved because substrate operates at N=1 even during transport outage. The substrate scales down to LoRa and up to broadband with the same primitives; connectivity conditions determine operational patterns without changing operational fundamentals.
