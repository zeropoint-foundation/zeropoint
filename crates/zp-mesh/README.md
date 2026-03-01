# zp-mesh

Sovereign mesh transport for ZeroPoint agents, compatible with the [Reticulum Network Stack](https://reticulum.network).

Agents discover each other, establish encrypted links, and exchange governance artifacts (receipts, delegations, audit challenges, reputation summaries, policy modules) over any physical medium — LoRa, WiFi, HaLow, Ethernet, serial, or TCP tunnels. The wire format is Reticulum-compatible: HDLC-framed packets with Ed25519/X25519 identities and 128-bit destination hashing.

## Design Principles

**Sovereign.** No DNS, certificate authorities, ISPs, or cloud infrastructure required.

**Identity = Keypair.** Addresses are derived from Ed25519 public keys via SHA-256 truncation to 128 bits.

**Encrypted by Default.** All traffic uses asymmetric encryption plus session keys derived from X25519 ECDH.

**Medium-Agnostic.** The same protocol runs over LoRa at 300 baud or fiber at 1 Gbps.

**Receipt-Native.** All agent exchanges produce verifiable receipts.

## Modules

### identity.rs — Cryptographic Identity

`MeshIdentity` holds an agent's Ed25519 signing key and X25519 encryption key. `generate()` creates a random identity; `from_ed25519_secret()` creates a deterministic one from a seed. Methods include `sign()`, `verify()`, `key_exchange()` (X25519 ECDH), and `derive_session_keys()` (HKDF to AES-128-CBC keys). `destination_hash()` computes the 128-bit address: SHA-256(signing_pub ‖ encryption_pub)[0:16].

`PeerIdentity` represents a known peer (public keys only), constructed from an announce packet's 64-byte combined key.

### packet.rs — Wire-Format Datagrams

Reticulum-compatible packet encoding. The wire layout is:

```
[Header1(flags)] [Header2(hops)] [Address(16)] [Transport?(16)] [Context?(1)] [Data(0-465)]
```

Header byte 1 encodes IFAC, header type, context flag, propagation type, destination type, and packet type. `PacketType` includes Data, Announce, LinkRequest, and Proof. `PacketContext` extends Reticulum with ZeroPoint-specific contexts: Delegation, PolicyAdvertisement, PolicyChunk, AuditChallenge, AuditResponse, ReputationSummary, and others.

Default MTU is 500 bytes (Reticulum standard). Maximum data payload for Type 1 headers is 465 bytes.

### link.rs — Encrypted Bidirectional Channels

Three-packet handshake for encrypted point-to-point links:

```
Initiator → LinkRequest  (ephemeral X25519 pub + Ed25519 pub + nonce)
Responder ← LinkProof    (Ed25519 signature + ephemeral X25519 pub)
Both      → Active link with AES-128-CBC session keys
```

Session keys are derived via HKDF from the X25519 shared secret. The initiator's encryption key is the responder's decryption key and vice versa. Keys are auto-zeroized on drop. Links support capability negotiation after establishment.

### envelope.rs — Governance Artifact Transport

Wraps receipts, delegations, and other governance artifacts for mesh transmission. Full JSON receipts (2-4 KB) don't fit the 465-byte packet MTU, so `CompactReceipt` uses msgpack with short field names (id, rt, st, tg, ch, ts) — typically 150-300 bytes. `CompactDelegation` similarly compresses capability grants.

`MeshEnvelope` is the signed outer wrapper carrying envelope type, sender address, sequence number, timestamp, msgpack payload, and a 64-byte Ed25519 signature. Envelope types include Receipt, Delegation, PolicyAdvertisement, PolicyChunk, AuditChallenge, AuditResponse, AuditAttestation, ReputationSummary, and several others.

### transport.rs — Agent Transport Bridge

`MeshNode` is the high-level transport interface. It manages interfaces, peers, links, delegations, audit attestations, and reputation state. Key operations include `announce()` to broadcast capabilities, `send_receipt()` and `broadcast_receipt()` for receipt distribution, `send_delegation()` for capability delegation, `send_audit_challenge()` and `send_audit_response()` for audit verification, `record_reputation_signal()` and `compute_peer_reputation()` for multi-dimensional reputation, `broadcast_reputation_summary()` for reputation propagation, `advertise_policies()` and `request_policies()` for WASM policy exchange, and `establish_link()` for encrypted connections with capability negotiation.

### interface.rs — Physical Medium Abstraction

The `Interface` trait abstracts over physical media: `send()`, `recv()`, `is_online()`, `stats()`. `InterfaceType` covers LoRa (500 MTU, 5 kbps), WiFi (1500 MTU, 100 Mbps), HaLow, Ethernet, Serial, TcpTunnel, UdpBroadcast, and Loopback. `LoopbackInterface` is provided for testing.

### tcp.rs — HDLC over TCP

Bridges internet TCP to the mesh via Reticulum-compatible HDLC framing: `[FLAG(0x7E)] [escaped_data] [FLAG(0x7E)]`. Bytes 0x7E and 0x7D are escaped with XOR 0x20. `HdlcDecoder` is a stateful stream decoder that reassembles frames. `TcpServerInterface` and `TcpClientInterface` implement the `Interface` trait.

### reputation.rs — Peer Trust Scoring

Multi-dimensional reputation scoring from governance evidence. `ReputationSignal` records a single evidence point in one of four categories: AuditAttestation, DelegationChain, PolicyCompliance, or ReceiptExchange, with Positive or Negative polarity.

`PeerReputation` is a per-peer ledger that accumulates signals (FIFO eviction at 100 per category). `compute_score()` produces a `ReputationScore` with an overall score (0.0–1.0), a `ReputationGrade` (Unknown, Poor, Fair, Good, Excellent), per-category breakdowns, and signal counts. Exponential time decay with a 30-day half-life favors recent evidence. Category weights are configurable (defaults: audit 0.35, policy 0.25, delegation 0.20, receipt 0.20).

### consensus.rs — Distributed Voting

Receipt-based multi-peer consensus. A `Proposal` is sent to designated voters with a threshold (Unanimous, Majority, or K-of-N). Each voter returns a `Vote` (accept or reject with reason). `ConsensusRound` tracks votes and evaluates the outcome.

### capability_exchange.rs — Link-Time Negotiation

Bilateral capability agreement when establishing a link. Each side presents a `CapabilityRequest` (what they want + what they offer) and a `CapabilityPolicy` (what they're willing to grant). The `negotiate()` function evaluates both directions and produces a `NegotiationResult` with grants for each side.

### policy_sync.rs — WASM Policy Propagation

Agents advertise available policy modules (`PolicyAdvertisement`), request specific modules by content hash (`PolicyPullRequest`), transfer WASM bytes in 350-byte chunks (`PolicyChunk`), and negotiate enforced policies via proposals and agreements.

### runtime.rs — Mesh Event Loop

`MeshRuntime` runs a background Tokio task that polls all attached interfaces, deserializes incoming packets, dispatches envelopes by type (receipt, delegation, policy, audit, reputation, announce), and feeds a channel for pipeline consumption. Configurable poll interval (default 50ms) and batch size (default 100 packets per cycle).

### store.rs — SQLite Persistence

`MeshStore` provides durable storage for mesh state across restarts. Five tables: peers (identity + capabilities), reputation_signals (per-peer signal history), delegation_chains (grant chains), audit_attestations (peer verification records), and policy_agreements (enforced policy sets). `open_memory()` for testing, `open(path)` for persistent storage. `MeshNode` integrates via `save_to_store()` and `load_from_store()`.

### destination.rs — Routing Primitives

`DestinationHash` is the 128-bit routing address. `DestinationType` selects encryption mode (Single asymmetric, Group symmetric, Plain broadcast, Link session). `Destination` combines a hash with an app name and aspects for Reticulum-style named routing.

## Reticulum Compatibility

Wire format, packet headers, addressing, MTU constraints, Ed25519/X25519 cryptography, destination hashing (SHA-256 truncated to 128 bits), announce packets, and the 3-packet link handshake all match Reticulum exactly. ZeroPoint agents can interoperate with Reticulum meshes via TCP tunnels.
