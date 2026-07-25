# Architecture Document — May 2026

*Companion to `docs/ARCHITECTURE-2026-04.md`. Captures what was learned during the May 6–7 invariantization sprint and the architectural realization about the substrate's outer API surface.*

*Status: Historical (as of 2026-07-10). Canonical substrate claims live in `KEEL-2026-07.md`; corpus map lives in `CANONICAL-CORPUS-INDEX-2026-07.md`. Retained for the specific sprint findings on API surface discipline and the Seam-22 realization. **Not amended for corpus pivots past July 2026.***

---

## Part I — Frame

### What changed today

May 6 closed Seams 1, 2, 3, 5, 8, 9a, 10, 11, 17, 19, and 20. By the end of the day every internal seam in the substrate that admits a singular-carrier closure was either closed or had a clean wire defined. The Tier-2 invariantization arc — fleet auth, announce replay, public-page supply chain — landed without major surprises. The pre-push hook caught the only real defect (an incomplete commit) and did its job.

May 7 was meant to continue that arc with Seam 12 (configuration provenance) and Seam 22 (API surface discipline). The schema work for Seam 12-B started cleanly. Seam 22 was where the architecture broke.

The break: while writing Seam 22's pending entry, the realization landed that ZP's *public-facing API surface* has been treated as a UI concern when it is actually a substrate concern. The 109 `/api/v1/*` HTTP routes have been accreting around the assumption that "an endpoint returns whatever JSON shape is convenient." That assumption was never examined because internal seams kept feeling more urgent. But the inversion was always there: the surface that needs the *most* discipline is the one facing outward, and we have been disciplining the inside while leaving the outside conventional.

The first attempt to articulate the fix landed wrong-shaped: "pixel-streaming for humans, receipts-only for agents." That formulation sounded clean but failed the Reticulum test. ZP is *designed* for environments where pixel-streaming is structurally impossible — packet radio, off-grid, disaster response, very-low-bandwidth mesh. A formulation that excludes those operator classes betrays the substrate's positioning.

The corrected formulation, which this document builds on, is: **the disciplined surface is the typed verb set; deliveries are plural.**

### Why this document exists

This document does three things:

1. **Records the load-bearing assumptions** that emerged from the May 6–7 conversation, so they don't have to be re-derived from chat logs.
2. **Surfaces the un-thought dimensions** of ZP's claims that the conversation made visible — places where the brand language commits to a property the code doesn't yet structurally support. These are not failures; they are honest acknowledgments of where conventions have been doing work that invariants should be doing.
3. **Re-maps the existing seam catalog** under the corrected frame, so the work-in-flight knows which arcs collapse, which transform, and which remain.

The document deliberately does not resolve the open architectural questions. The regroup is for that. Producing a draft full of decisions would short-circuit the thinking that needs to happen.

---

## Part II — Decisions made (load-bearing)

The following are committed enough that the rest of this document builds on them. If any need re-examination, flag them; otherwise they're the foundation.

### 0. Meta-principle — Contracts are singular; implementations are plural

The substrate is **hexagonal at every architectural seam.** A *contract* (port) is one shape — a singular schema, protocol, ceremony, or wire format — and admits no alternatives. An *implementation* (adapter) is one of many concrete realizations of a contract — it serves a specific operator class, environment, external dependency, or hardware target, and other implementations of the same contract may exist alongside it without contradiction.

**Contracts in ZP** (singular by design):

- The verb set (one schema; per-verb response category declared in the schema).
- The receipt format (one canonical shape; hash-then-sign).
- The audit chain format (one append-only log shape).
- The Genesis ceremony (one ceremony per node).
- The hash-then-sign discipline (one rule, no exceptions).
- The mesh `Interface` trait (one port; multiple transport adapters).
- The `SovereigntyProvider` trait (one port; multiple device adapters).

**Implementations in ZP** (plural by design):

- Operator-environment deliveries (native, WebRTC stream, CLI/HTTP, CLI/Reticulum, sneakernet, SDK).
- Peer transports (Reticulum, libp2p — and within libp2p: QUIC, TCP, WebSocket, WebRTC).
- Subscription transports (gossipsub, HTTP webhook, Reticulum push, mesh push).
- Sovereignty providers (Touch ID, fingerprint, Windows Hello, Trezor, YubiKey, Ledger, OnlyKey, file-based, login password).
- Streaming transports (gRPC streaming, SSE, WebSocket, gossipsub).

**The discipline that flows from it:**

- *At the contract layer:* schema versioning, discipline pins, formal change ceremony. Adding a second contract for the same concern is the warning sign; modifying an existing contract requires version-bumping discipline.
- *At the implementation layer:* every adapter must carry a doc comment naming the port it adapts and the operator class / external dep / use case it serves. Adding an adapter is a deliberate act, not a drive-by; CI enforces the documentation. Removing an adapter requires showing no operator class still depends on it.

**The counterbalance:** plurality at the adapter layer is not a license for sprawl. The discipline at the adapter layer is *justification per instance*, not *uniformity across instances*. Each adapter exists for a reason that is documented in code, in this architecture doc, or both.

**The architectural test:** for any seam, the question is "port or adapter?" If port, choose carefully — there can be only one shape, and it must serve every adapter. If adapter, choose for fit — it must serve its operator class, and other adapters may serve other classes simultaneously. Misclassifying a seam (treating an adapter as a port, or a port as an adapter) is the failure mode that produces either over-coupling or sprawl.

This principle is the one we've been converging on without naming, going back through the April invariantization arc. The May 8 conversation surfaced it explicitly; it's recorded here so future architectural decisions have a frame to reference.

### 1. Receipts are the typed boundary

Every interaction with the substrate that affects state is a typed receipt-issuing call. The verb set is bounded; the verbs produce or consume receipts; nothing else. There are no "ad-hoc JSON shapes" anywhere on the public surface. The mesh wire (already disciplined: 17 typed `EnvelopeType` variants, msgpack, signed) is the existence proof that this kind of discipline is achievable. The HTTP wire becomes the conformity case.

### 2. Deliveries are plural

A single delivery mechanism cannot serve every operator class ZP positions itself for. The substrate commits to multiple delivery mechanisms — native in-process, pixel-streamed UI, CLI over HTTP/SSH, CLI over Reticulum, sneakernet for air-gapped — and the verb set is reachable through each. Plurality at the delivery layer; singularity at the verb layer.

### 3. Reticulum compatibility is non-negotiable

Operator-access shapes that exclude Reticulum-class deployments (300 bps – 9.6 kbps, async, store-and-forward) are not acceptable. ZP's positioning explicitly includes off-grid, disaster-response, and censorship-resistant scenarios, and `crates/zp-mesh/src/reticulum_discovery.rs` already implements the agent-side wire. The operator-side wire must reach the same environments.

### 4. The 109-route HTTP API as it stands retires

The current `/api/v1/*` surface is structurally undisciplined relative to the substrate's claims. It will not be iterated; it will be redesigned around the verb set. The dashboard backend it serves is replaced by deliveries 1–2 (native in-process / pixel-streamed UI). The third-party-agent path it served is replaced by deliveries 5–6 (mesh envelopes / typed SDK bindings).

### 5. "Best part is no part" applies — but scoped

The principle is correct: most of what we have been doing is *adding* structural force, and the inverse move (remove the surface that needs disciplining) is sometimes the right one. But it applies to *undisciplined surfaces*, not to the substrate's stated capabilities. We remove the JSON-API-handler-zoo. We do not remove "operator can interact with their node from a low-bandwidth network."

### 6. ZP commits to both Reticulum and libp2p, in full

The substrate's mesh layer supports two complementary peer-to-peer stacks, neither as fallback for the other:

- **Reticulum** (existing in `crates/zp-mesh/src/reticulum_discovery.rs`) — radio mesh, packet radio, LoRa, audio modems. 300 bps – 1.2 Mbps. Store-and-forward (LXMF). No infrastructure dependency. Off-grid, censorship-resistant, disaster-response.
- **libp2p** (new commitment) — internet-scale P2P. Used at scale by Ethereum, Filecoin, IPFS. Brings: peer discovery (Kademlia DHT, mDNS, rendezvous), NAT traversal (DCUtR, AutoNAT, hole punching), multiple transports (TCP, QUIC, WebRTC, WebSocket, WebTransport — selected deliberately, not all enabled), stream multiplexing (yamux, QUIC native), pub-sub (gossipsub), content routing (find peer holding a hash), encrypted-by-default (Noise / TLS 1.3).

The two stacks cover the full bandwidth/connectivity spectrum. A ZP node can speak one, the other, or both. Bridge nodes participating in both networks are first-class architectural objects — the mesh `Interface` abstraction in `zp-mesh` accepts both as peer transports, and the routing layer dispatches "send receipt to peer X" without the caller knowing which network reaches X.

**Identity invariant.** A node's `MeshIdentity` (combined Ed25519 + X25519) produces both a Reticulum destination hash and a libp2p PeerId deterministically. Same key, two addresses, reversible. No third identity primitive.

**Sub-decisions remain open.** Which libp2p transports to enable (QUIC primary likely; WebSocket for browser-reachable; WebRTC overlaps with delivery 4.2). Whether gossipsub becomes a fourth subscription transport alongside HTTP webhooks, Reticulum push, and mesh envelope push (probably yes). How chain-segment retrieval composes with libp2p's content routing for V.1 (trust portability). These are tomorrow's design tasks; the commitment to both stacks is settled today.

> **Update (May 8 2026):** Sub-decisions resolved by the technology-landscape survey (`docs/TECH-LANDSCAPE-2026-05.md`). See decisions #10, #11, #12 below.

### 7. Protobuf is the verb-set schema layer

The substrate's verb set is defined in `proto/zp_v1.proto` (or equivalent). Protobuf is the source of truth for response shapes and request types regardless of which transport carries the bytes. Generated Rust types replace today's hand-rolled `*Response` structs. Generated TS/Python/Go bindings replace today's hand-rolled SDK clients. Versioning discipline (protobuf field numbering) replaces today's implicit versioning.

This decision is independent of #8 (gRPC adoption). Protobuf-as-IDL gives schema-as-source-of-truth even if the transport underneath is msgpack envelopes or libp2p streams. The schema layer composes across all transports; the wire format underneath is an implementation detail.

### 8. gRPC + tonic for the SDK boundary

Delivery 4.6 (third-party agent SDK) uses gRPC over HTTP/2 with tonic on the Rust side. Streaming verbs (`TailEntries`, `WatchReceipts`, etc.) use gRPC's native server-streaming primitive. Browser-resident SDK consumers may use ConnectRPC (gRPC-compatible, simpler browser story) — adoption of Connect deferred until concrete browser SDK consumers exist.

Decision is conditional on #7 (protobuf adoption). The `.proto` schema is the contract; gRPC is the natural transport for that contract.

### 9. WebRTC + Selkies-GStreamer for delivery 4.2

Delivery 4.2 (pixel-streamed remote UI) uses WebRTC for transport and Selkies-GStreamer for server-side capture-and-encode. Browser is the client; zero install. Hardware encoder support: NVENC (NVIDIA), VAAPI (Intel/AMD), VideoToolbox (macOS server, when applicable). Sunshine + Moonlight is a secondary option for latency-priority operators willing to install the Moonlight client; not the default path.

WebRTC's overlap with #10 (libp2p WebRTC transport) and verb data channels (architecture Part IV.6) is a feature: the same TURN/STUN infrastructure, encoder hardware, and signed-SDP authentication serve all three.

### 10. libp2p default transports: QUIC + TCP + WebSocket + WebRTC

Of libp2p's transport set, the default build enables:

- **QUIC** — primary. Encrypted, low-latency, multiplexed.
- **TCP** — fallback for environments where QUIC is firewalled (some corporate networks, legacy ISPs).
- **WebSocket** — browser-reachable peers and restrictive networks where QUIC and direct TCP fail.
- **WebRTC** — browser-direct peers and the cross-cutting overlap with delivery 4.2. Single primitive; triple use.

**WebTransport** is deferred until Safari ships support. Track upstream; revisit when adoption justifies a second browser-side streaming wire.

### 11. gossipsub for ZP-to-ZP subscriptions

When both publisher and subscriber are libp2p peers, subscriptions ride gossipsub topics. Topic naming convention encodes filter shape (`/zp/receipts/v1/<filter>`); receipts published to topics retain their signatures. The substrate publishes; subscribers in the topic mesh receive.

This is the ZP-to-ZP path of delivery 4.7. HTTP webhooks remain the path for non-ZP subscribers; Reticulum / mesh-envelope push remain for off-grid subscribers. The split is by subscriber class, not by transport preference — each transport serves the subscriber class it can reach.

### 12. Trust portability via OpenTimestamps + Bitswap + gossipsub (composed)

V.1 (trust portability) is closed as a three-part composition:

- **OpenTimestamps** anchors chain-head hashes to Bitcoin via Merkle aggregation. Hour-to-day granularity. Lightweight (no Bitcoin node required); verification is self-contained from the proof file.
- **libp2p Bitswap + Kademlia DHT** retrieves chain segments by content-address hash. A verifier with a receipt asks "who has this segment hash?" via Kademlia and pulls from any peer that answers, via Bitswap.
- **gossipsub** propagates new receipts in real-time to mesh subscribers (composed with #11).

Full IPFS is not adopted; the underlying libp2p protocols (Bitswap, DHT) are. This composition closes both V.1 and V.5 (anchoring threat model) — the threat model V.5 enforces is stated explicitly: **OpenTimestamps anchoring defends against retroactive chain rewrites at hour-to-day granularity. Sub-hour rewrites are not in this defense's scope; the chain's own hash-linked structure handles them.**

### 13. Pure gRPC; HTTP/JSON deprecated entirely

The substrate exposes its verb set over **gRPC only** (Architecture II.8). HTTP/JSON — including Connect-mediated, schema-bound HTTP/JSON — is deprecated and not exposed. The 109-route ad-hoc HTTP API retires (II.4); no HTTP/JSON variant of the verb set replaces it.

**Rationale.** ZP's central thesis is minimum-surface trust. JSON adds attack-surface classes that protobuf doesn't have: number type confusion (signed-int validation bypassable via float coercion), parser CVEs (billion-laughs, deep nesting, Unicode normalization, escape edge cases), and unknown-field tolerance (servers process unexpected fields by default). HTTP/JSON also reintroduces CSRF/CORS surface for browser clients absent from server-only gRPC. The "operator wants to curl things" ergonomic argument is satisfied by the `zp` CLI binary (a gRPC client that prints responses for human reading), not by exposing an HTTP/JSON wire.

**Reserved exceptions** (added when concrete need surfaces; not in v1):

- *Inbound webhook ingestion* (Slack slash commands, monitoring alerts triggering verbs) — if needed, lands as a deliberately-narrow inbound HTTP endpoint with a strict allowlist of accepted operations. Not a "verb set in HTTP form" — a separate, scoped surface.
- *Browser SDK access* — if needed, lands as **gRPC-Web** (gRPC over HTTP/1.1, no JSON wire). Avoids JSON's CVE class while keeping schema-bound discipline.

**What this changes downstream.**

- **Delivery 4.3 (CLI / remote)** — wire is gRPC over HTTP/2 + TLS, or SSH-tunneled gRPC. The CLI binary speaks gRPC; users see the ergonomic shell.
- **109-route retirement (Phase 2 work)** — the ~52 routes that currently subsume into the verb set become tonic gRPC handlers. The ~44 ad-hoc routes delete outright.
- **Discipline pin `verbs_must_match_schema`** — no behavioral change; tonic's compiler-enforced trait conformance covers the gRPC-only case.

---

### 21. Singular sovereign root — one ceremony per process lifetime

*Landed 2026-05-14. Commits 7f6397b + eb1975f + aba2b26 + 7a9d30d. Task #152.*

There is exactly **one sovereign root** in any ZeroPoint process: Genesis. Every
other sensitive value is either:

1. **Derived from Genesis in memory** — vault master key (`BLAKE3(genesis,
   "zp-credential-vault-v1")`), audit signer seed (`derive_audit_signer_seed`),
   agent certificate material. Never stored independently.
2. **Stored in the vault** (`vault.json`, ChaCha20-Poly1305 at rest) and
   decrypted on demand using the in-memory vault master key from (1).

There is no third category. No other secret lives in the OS credential store
with its own biometric gate.

**The canonical loader** is `zp_keys::sovereignty::load_sovereign_root()`. It
wraps a process-scoped `OnceLock` — one sovereignty ceremony per process
lifetime. Fast path: standard OS Keychain (already cached from the OnceLock in
`load_genesis_from_credential_store`). Provider path: reads `genesis.json` to
determine mode and invokes the appropriate hardware-wallet or software provider.

**Under II.0:** `load_sovereign_root()` is the **port** (singular). Touch ID,
login-password, file-based, Trezor, YubiKey, M-of-N quorum — these are the
**adapters** (plural). Callers see one surface; the surface hides which
ceremony the operator has enrolled.

**Why this is load-bearing:** direct credential-store reads scattered across
call sites multiply with every new sovereignty provider added. With M-of-N
quorum sovereignty (CLAUDE.md, Architecture Direction), each independent
credential-store read becomes M ceremonies instead of 1. The singular-root
discipline makes M-of-N tractable.

**Discipline pin** `singular_sovereign_root` in `docs/DISCIPLINE-PINS.md`
mechanically enforces the boundary: `keyring::Entry::get_password()` outside
`crates/zp-keys/src/keyring.rs`, `SecItemCopyMatching` outside `touchid.rs`,
and direct `provider.load_secret()` calls outside `sovereignty/mod.rs` are
all CI-failing violations.

**Migration on APOLLO (2026-05-14):** three Keychain entries found where one
was expected. Two were vestigial (`zeropoint/vault-master-key` — relic from a
pre-Genesis design; `zeropoint-operator/operator-secret` — best-effort cache
never read back). Both removed from write paths; `zp keychain cleanup --delete`
removes the stale entries from existing operator machines.

*Full argument: `docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md`.*

---

### Reconciliation — the April doc's seven design principles under II.0

Part V½ of `docs/ARCHITECTURE-2026-04.md` lists seven design principles for the substrate. Principle II.0 above does not replace them; it refines them by giving each a structural location. The seven principles remain authoritative; II.0 names where each lives.

| April Principle | Classification under II.0 | Why |
|---|---|---|
| 1 — Signing is gravity | **Port** | "Every claim carries a signature" is a singular contract. The signing key varies per operator (adapter); the *requirement* of signing does not. |
| 2 — Identity is a key, not a location | **Port** | "Identity is cryptographic lineage" is a singular contract. Where the key is stored (Touch ID, Trezor, file) is the plural adapter layer. |
| 3 — There is no center | **Meta-architectural** | Specifically about adapter plurality at the trust-source layer. No single adapter may be the universal source of truth. The local audit chain is the contract; nodes adapting it independently is the principle's force. |
| 4 — Every bit counts | **Port** | "Every field is load-bearing" is a discipline applied uniformly to all schemas. Singular. |
| 5 — Store-and-forward primary | **Adapter** | About how implementations operate: nodes adapt to varying connectivity by treating the chain as the source of truth. Plural connectivity environments; one chain contract. |
| 6 — A tool is intent, crystallized | **Port** | "Semantics in structure, not in comments" is a singular discipline applied to every schema/format. |
| 7 — Contact does not commit | **Port** | "Receipts are chosen, not transcribed" is the contract that distinguishes events that reach the substrate from those that update it. Singular. |

Five of seven principles are port-shaped (singular contracts). One is adapter-shaped (the implementation landscape varies; nodes adopt store-and-forward differently). One is meta-architectural (Principle 3 is *specifically* prescribing adapter plurality where centralization could otherwise creep in — a constraint on how ports are implemented, not a port itself).

This split is consistent with the catalog audit (`STRUCTURAL-AUDIT-2026-05.md` Part II): most of the substrate's load-bearing work is port discipline, with a smaller layer of adapter discipline that requires per-instance justification. The principles align with the practice; the practice extends the principles into specific cases (verb set, deliveries, peer stacks, sovereignty providers).

**II.0 doesn't change any April principle.** It gives them a frame: when applying any of the seven, ask "is this asking me to enforce a contract or shape an adapter set?" The classification above answers for each. Code that violates one of the seven principles is wrong for the reasons the April doc states; II.0 helps locate *where* the violation lives — at the port layer (a contract has been weakened or duplicated) or at the adapter layer (an adapter has been added without justification, or all adapters have collapsed to one when plurality was the point).

---

## Part III — The verb-set principle

### What a verb is

A verb is a typed, named operation that produces or consumes one or more receipts. Examples (illustrative, not final):

- `evaluate` — input: gate request; output: a `GuardReceipt` attesting the verdict.
- `grant` — input: capability grant request; output: a `DelegationReceipt`.
- `audit_verify` — input: chain segment selector; output: an `AttestationReceipt`.
- `announce` — input: agent capabilities; output: a `SignedAnnounce` envelope (already disciplined in `crates/zp-mesh`).
- `chain_head` — input: none; output: a chain-head receipt with the latest entry hash + signature.

The verb's *type signature* is the contract. The verb's *implementation* is one or more receipt-producing operations. The verb is reachable through every delivery; the implementation is the same regardless of delivery.

### What is not a verb

- A request that returns ad-hoc JSON.
- A request that reads system state without producing a receipt of having done so.
- A request that mutates state without producing a receipt.
- A request whose input or output isn't part of the typed schema.

There are *infrastructure resources* that aren't verbs — `/health`, `/version`, the SSE event stream, static assets, the WebRTC signaling endpoint. These live on a documented allowlist. They don't issue receipts. They are not part of the verb set. They are explicitly bounded.

### Why this is the right altitude

ZP claims trust is structural. A verb-set boundary makes the claim true at the API surface. A third party building an SDK against ZP can know — from the schema, not from observation — what shapes are possible to receive. A verifier replaying a session can know that every observable interaction left a receipt. A discipline pin can fail the build if a handler returns something that is not a verb result.

The mesh wire already works this way. The HTTP wire becoming this way is the conformity case.

### What about reads?

Many of the existing 109 routes are reads — `/api/v1/audit/entries`, `/api/v1/identity`, `/api/v1/stats`. They don't mutate state; they expose state. The question of whether a read should produce a receipt has two honest answers:

1. **Reads do produce receipts** (a `QueryReceipt`, attesting "at time T, this query returned this answer signed by the node"). This makes audits of what-was-observable possible. Costs: every dashboard refresh becomes a receipt; the chain grows fast.
2. **Reads return typed-but-unsigned envelopes** (a `QueryEnvelope`, typed by the schema but not signed or chained). This keeps the chain small. Costs: the verb-set discipline weakens; "read" becomes a special case.

Resolution: open. See Part VII.

---

## Part IV — Delivery mechanisms

The verb set is reachable through each of these. Each is optimised for a different operator environment.

### 4.1 Native in-process

**Operator class:** Operator on the same machine as their ZP node.

**Mechanism:** The dashboard is a native UI process (Tauri / iced / egui / Slint — choice open). It links the ZP runtime as a library, or talks to the runtime over a Unix domain socket only `root@local` can access. Receipt-issuing verbs are direct function calls.

**Properties:**
- No network involvement. No streaming. No JSON. No tokens.
- Strongest "no part" — there is effectively no API in this path.
- Attack surface: native binary integrity + local IPC.

**Trade-offs:** Limits multi-user scenarios on the same node (multiple humans simultaneously operating the same node would each need a session, and Unix-socket auth doesn't naturally distinguish them). Acceptable for the single-operator-per-node case; needs revisiting for fleet operators.

### 4.2 Pixel-streamed remote UI

**Operator class:** Operator on a different device with good connectivity (broadband, modern cellular, decent corporate wifi).

**Mechanism:** The native UI from §4.1 runs server-side. Its rendered output is captured and streamed via WebRTC. Input events flow back over a data channel.

**Properties:**
- Zero client install (browser is the client) when WebRTC is the transport.
- Bandwidth: ~1–5 Mbps for a usable experience; sensitive to <300ms RTT.
- Attack surface on the client: the streaming protocol only. No JS execution, no JSON parsing, no client-stored tokens, no XSS, no CSRF.
- Authentication: SDP exchange happens through the mesh signaling channel. Operator's keys sign the SDP offer; endpoint accepts only signed offers. No new auth scheme.

**Tech candidates** (decision deferred to Part VII):
- **Selkies-GStreamer** — Linux server-side, production-grade (Google Cloud Workstations).
- **Neko** — BSD-3, Docker-based, simpler ops.
- **Sunshine + Moonlight** — gaming-grade latency; requires Moonlight client install (not browser-only).
- **Apache Guacamole** — pure HTML5, simpler architecture, lower video quality.

**Trade-offs:** Bandwidth/latency cost is real. Operators on flaky connections experience visible degradation; operators on high-latency satellite or aircraft wifi find it unusable. This is the explicit reason §4.3–4.4 exist.

### 4.3 CLI over gRPC / SSH

**Operator class:** Operator on a constrained but functional internet connection — cellular brownouts, hotel wifi with bad infra, corporate networks where WebRTC is firewalled, rural fixed wireless.

**Mechanism:** A CLI binary (`zp <verb> ...`) that talks to the local-or-remote ZP runtime. Each verb invocation is one receipt-issuing call. Transport is **gRPC over HTTP/2 + TLS, or SSH-tunneled gRPC** (per Architecture II.13 — pure gRPC; HTTP/JSON deprecated). The CLI binary speaks gRPC; users see only the ergonomic shell. Responses can be printed as JSON for human reading via `--json` flag, but the wire format is protobuf throughout.

**Properties:**
- Bandwidth: tens of kbps tolerated; each verb call is on the order of receipt-size (hundreds of bytes to a few KB).
- Latency: high tolerance — the user expects to wait for a CLI invocation.
- Disconnect recovery: per-call retries; partial-state failures are receipt-shaped (an issued receipt exists or it doesn't).
- Survives most environments where the dashboard fails.

**Trade-offs:** No live UI. The operator gives up rich interactivity for connectivity tolerance. For most field/travel scenarios this is the right trade.

### 4.4 CLI over Reticulum

**Operator class:** Operator on a radio mesh, off-grid, packet-radio link, LoRa node, or any Reticulum-routed network.

**Mechanism:** The same CLI verb set, transported over Reticulum (LXMF-shaped, or via the existing `crates/zp-mesh/src/reticulum_discovery.rs` envelopes). Asynchronous by default — verb invocations may be store-and-forward; results may arrive minutes or hours later.

**Properties:**
- Bandwidth: 300 bps – 1.2 Mbps. Functional even at the low end.
- Latency: high. Store-and-forward is normal.
- No infrastructure dependency. Survives internet partition.
- Attack surface: Reticulum's cryptographic destination model + the verb set's signature discipline.

**Trade-offs:** Asynchronous semantics force receipt-shaped operations. Live debugging is impractical. This is exactly the scenario ZP is *positioned for* — the trade-offs are aligned with the operator class's expectations.

### 4.5 Air-gapped / sneakernet

**Operator class:** Operator in an environment where no network connection at all is acceptable (high-security, classified, deeply hostile).

**Mechanism:** Verb invocations are produced as detached signed messages (e.g. JSON, msgpack, or QR-encoded), physically transported (USB, paper, optical), and applied at the destination node. Same verb set; transport is sneakernet.

**Properties:**
- Bandwidth: arbitrary; latency: arbitrary.
- No live interaction.
- Attack surface: physical media handling.

**Trade-offs:** Most extreme. Not every verb makes sense in this delivery (e.g. anything requiring round-trip handshakes); the verb set may need to declare which verbs support detached invocation.

### 4.6 Third-party agent (SDK)

**Operator class:** A non-ZP system or third-party agent that needs to interact with a ZP node.

**Mechanism:** Receipts in, receipts out. Two transport options:
1. **Mesh envelopes** — already disciplined, msgpack, low-bandwidth-friendly.
2. **gRPC** — typed bindings generated from the verb-set schema. Universal client tooling (Rust/TS/Python/Go/Java).

Choice between these is open (Part VII).

**Properties:**
- The SDK is *not the dashboard*. SDK consumers don't get a UI; they get verb invocations.
- The verb set is the typed contract.

**Trade-offs:** Adopting gRPC is the cleanest answer to the SDK boundary, but it adds tooling overhead (protoc, codegen). Sticking with msgpack envelopes is lighter but harder for SDK consumers to onboard.

### 4.7 Streaming, subscription, and outbound (WebSockets, webhooks)

Deliveries 4.1–4.6 are framed as *inbound, request/response* — operator invokes a verb, gets a receipt. Two interaction patterns aren't covered by that frame and need explicit treatment, because real ZP use cases need them and "no part" doesn't apply (these patterns *do* belong; they just need to be disciplined under the verb set, not removed).

#### Pattern A — streaming response

An operator/agent invokes a verb and receives a stream of receipts instead of a single one. Examples: tailing the audit chain, watching delegation events, monitoring a long-running gate evaluation.

Under the verb set, this is a *streaming response verb* — same typed contract as a non-streaming verb, but the response type is `stream T` rather than `T`. Transport choices for the streaming pattern:

- **gRPC server-streaming** (delivery 4.6) — typed, native.
- **SSE** (delivery 4.3) — HTTP-native, one-way, simple.
- **WebSocket** (delivery 4.3) — HTTP-upgrade, duplex; equivalent in capability to gRPC streaming, different wire.
- **Mesh envelope sequence** (deliveries 4.4, 4.6) — already shape-compatible.
- **In-process channel** (delivery 4.1) — `tokio::sync::mpsc` or similar.

**WebSockets are a transport choice, not a delivery.** They live inside delivery 4.3 as the duplex option for streaming/subscription patterns. Every WebSocket frame is either a verb invocation or a receipt response; the verb-set discipline still holds. They evaporate from delivery 4.2 (pixel-streaming) because the dashboard's "live updates" come from the server rendering its own state, not from pushing JSON to a client.

#### Pattern B — subscription / outbound (webhooks)

The substrate notifies an external system when a receipt matching a filter is issued. Examples: PagerDuty on critical gate failure, Slack on delegation grant, status page on chain-head update, monitoring system on policy module load.

This is the first *outbound* delivery — the substrate is the client; the subscriber is the server. Composition with the verb set:

1. Operator invokes `Subscribe(filter, target, secret)`. Normal inbound verb; produces a `SubscriptionReceipt` recording the subscription terms.
2. When a receipt matches `filter`, the substrate pushes the receipt to `target` over the appropriate transport.
3. `Unsubscribe(subscription_id)` produces a cancellation receipt.

The payload pushed is a *typed receipt*, not ad-hoc JSON. The subscriber's `target` must accept receipt-shaped messages; if it doesn't, that's the subscriber's adapter problem, not the substrate's.

Transport choice depends on `target`:

- `https://...` URL → HTTP POST (classic webhook). Body = receipt; `secret` HMACs the body for provenance.
- Reticulum address → LXMF-shaped push (delivery 4.4 outbound).
- Mesh peer hash → msgpack envelope push (delivery 4.6 outbound).

The pattern is "outbound subscription"; the transport varies by subscriber address shape. Webhooks (HTTP) are the most common case; Reticulum and mesh-peer pushes serve the off-grid and inter-node-fleet cases respectively.

#### Why this preserves the discipline

WebSockets and webhooks fit the verb-set frame because:

- Every WebSocket frame is a verb invocation or a receipt response. No ad-hoc JSON shapes appear.
- Every webhook POST body is a signed receipt. Subscribers verify it via the `secret` HMAC and the receipt's signature. No ad-hoc JSON shapes appear.
- The substrate's outbound surface is "receipts only," same discipline as the inbound surface.

What doesn't fit the verb-set frame (and is therefore forbidden):

- Server-pushed events that aren't receipts.
- Webhook POSTs with custom JSON envelopes wrapping the receipt.
- WebSocket frames carrying anything other than verb invocations or receipts.

### Summary table

| # | Operator environment / pattern | Direction | Bandwidth | Latency | Key property |
|---|---|---|---|---|---|
| 4.1 | Same machine | In | n/a | n/a | No network, no API |
| 4.2 | Good remote (pixel stream) | In | 1–5 Mbps | <300ms RTT | Zero client install |
| 4.3 | Constrained remote (CLI/HTTP, +SSE/WebSocket for streaming) | In | tens of kbps | tolerant | Survives most networks |
| 4.4 | Reticulum / radio mesh | In, also Out (push) | 300 bps+ | async | Off-grid functional |
| 4.5 | Air-gapped | In | arbitrary | arbitrary | Sneakernet |
| 4.6 | Third-party agent (mesh / gRPC, +server-streaming) | In, also Out (push) | flexible | flexible | Typed contract |
| 4.7 | Subscription / webhook | Out | flexible | flexible | Outbound notification |

---

## Part V — Un-thought dimensions

These are dimensions of ZP's claims that the May 6–7 conversation surfaced as having been hand-waved. Each is real. Each is unresolved. The regroup is for resolving them.

### V.1 — Trust portability  ✅ Resolved (May 8 2026, see Part II.12)

**Decision:** Hybrid composition — OpenTimestamps for chain-head anchoring, libp2p Bitswap + Kademlia DHT for chain-segment retrieval, gossipsub for live propagation. Full IPFS not adopted; underlying libp2p protocols are. See Part II.12.

The brand language says "portable trust infrastructure for the Agentic Age." The audit chain is local; the trust is supposed to be portable; the bridge between those two is hand-waved.

**What's missing:** A specified mechanism for an agent on system A to trust a receipt issued on system B. Chain segments need to flow; how? Pull-when-needed? Continuous gossip? Anchored to DLT and recoverable from there? Sufficient to verify a single receipt vs. sufficient to verify a chain segment vs. sufficient to verify an agent's full trust history?

**Options:**
1. **DLT-anchored portability** — periodic anchoring to a public DLT (e.g. via OpenTimestamps) lets any third party re-derive trust state from the public ledger + the local segment.
2. **Gossip-based portability** — receipts and chain segments propagate through the mesh; trust state is eventually-consistent. With the libp2p commitment, this is concretely *gossipsub* for receipt propagation and *Kademlia DHT* for peer discovery.
3. **Pull-on-demand via content routing** — the verifier asks "who has this chain segment hash?" via libp2p's content routing; pulls from whoever responds. Combined with the audit chain's hash-linked structure, this gives V.1 a concrete mechanism: chain segments are content-addressable; libp2p discovers and transports them.
4. **Hybrid** — anchoring (1) for finality, gossipsub (2) for liveness, content-routed pull (3) for verifying specific receipts. This is probably the right shape now that both Reticulum and libp2p are committed; the question is which subset is load-bearing for which property.

**What it affects:** Claim 4 (independent verification) directly. Currently a verifier can re-run a receipt's signature check but cannot independently obtain the chain context it needs. The libp2p commitment (Part II.6) gives this dimension concrete primitives to compose against; the design call is which composition.

### V.2 — Quorum sovereignty

The 1:1 sovereignty path (one Genesis key, one device) is complete. Multi-device, multi-person, threshold, recovery-from-loss are anticipated in `CLAUDE.md` ("design from the ground up for multi-signing/quorum") but no primitives exist.

**What's missing:** Mechanism for M-of-N signing of substrate-critical operations. A `SovereigntyProvider` trait that handles per-device shares + threshold reconstruction. A ceremony for adding/removing devices from a quorum without losing existing signed history.

**Options:**
1. **Shamir Secret Sharing** — split the Genesis seed into N shares, reconstruct on use. Simpler. Single point of failure during reconstruction.
2. **Threshold signatures** — each device signs independently, signatures combined off-chain. More powerful (no full key reconstruction). Requires curve-specific protocols (FROST for Ed25519).
3. **Hierarchical delegation** — Genesis remains 1:1, but issues delegation receipts to N devices each with constrained authority. Approachable today; weaker than true quorum.

**What it affects:** Sovereignty's load-bearing claim (the operator owns their identity). The 1:1 path is sufficient for personal use; institutional / multi-stakeholder deployments need more.

### V.3 — Delegation withdrawal

Capabilities delegate downward; the delegator can revoke a delegation by issuing a withdrawal receipt. But the *mechanics* of withdrawal-when-the-delegator-is-offline, or withdrawal-when-the-delegate-has-gone-rogue, are not specified.

**What's missing:** A specified protocol for trust withdrawal that doesn't require the delegator's online presence. A specified protocol for a third party to detect a stale-but-not-yet-withdrawn delegation. A specified protocol for race conditions (delegate exercises capability *during* the withdrawal flight).

**Options:**
1. **TTL-based delegations** — every delegation has an expiry; long-lived authority requires re-issuance. Simple. Imposes operational overhead.
2. **Dead-man's-switch** — delegator's continued presence (heartbeats) implies delegations remain valid; absence triggers automatic expiry. Requires liveness assumption.
3. **Quorum-revocable** — withdrawal receipts can be issued by a quorum of co-trustees, not just the delegator. Combines naturally with V.2.
4. **Reputation-driven** — delegations weaken as the delegate's reputation degrades; withdrawal becomes implicit. Requires the reputation system to be load-bearing.

**What it affects:** Principle 7 (contact does not commit). Without a withdrawal mechanism, contact effectively *does* commit until the delegator is back online to revoke.

### V.4 — Trust tier transitions

Tiers exist as a concept (`tier0`, `tier1`, etc.). The mechanics of how an agent moves between tiers — who decides, what's the evidence requirement, is it a receipt event — are sketched in whitepapers, not implemented.

**What's missing:** A specified protocol for tier transitions. A specified evidence requirement. A specified appeals/dispute path.

**Options:**
1. **Reputation-driven transitions** — accumulating positive receipts above a threshold elevates tier; negative receipts demote. Algorithm-driven, no human involvement.
2. **Vouched transitions** — higher-tier agents issue tier-elevation receipts for lower-tier agents they trust. Web-of-trust shape.
3. **Constitutional transitions** — policy modules define the transition rules; transitions are gate evaluations against those policies.

**What it affects:** The substrate's claim that trust is constructive. Without specified transitions, "trust tier" is a label that doesn't mean anything operationally.

### V.5 — Anchoring threat model  ✅ Resolved (May 8 2026, see Part II.12)

**Decision:** Adopt OpenTimestamps for chain-head anchoring. Threat model stated explicitly: defends against retroactive chain rewrites at hour-to-day granularity (Bitcoin block-time bounded). Sub-hour rewrites are out of scope for anchoring; the chain's own hash-linked structure handles them. The existing `dlt_enabled` / `dlt_network` config knobs are repurposed or retired in favor of the OpenTimestamps integration. See Part II.12.

DLT anchoring exists in config (`dlt_enabled`, `dlt_network`) but the threat model — what an anchor actually protects against — has not been clearly stated.

**What's missing:** An explicit statement of which attacks anchoring defends against and which it does not. Tampering at what altitude? Time-walked attacks? Network-partition rollbacks? Selective-memory replays?

**Options for resolution:** Write the threat model down explicitly. The anchoring code is already present; making the *purpose* of that code explicit is the missing piece.

**What it affects:** Whether anchoring is load-bearing or decorative. Currently unclear which.

### V.6 — Pipeline determinism

Receipts are signed, but is the pipeline that produces them strictly deterministic given the same input + the same config snapshot? Replay assumes yes. The codebase does not assert it.

**What's missing:** An explicit statement that the pipeline is deterministic. A discipline that detects non-determinism (e.g. wall-clock reads, random sources, hashmap iteration order). Test infrastructure that runs the same input twice and asserts identical output.

**Options:**
1. **Assert determinism, enforce structurally** — discipline pin forbids non-deterministic reads in the pipeline. Replay-test infrastructure verifies.
2. **Don't claim determinism** — accept that two runs may differ in non-load-bearing fields (timestamps, IDs) and design verification around that. The receipt's hash must be over the *deterministic* preimage only.
3. **Hybrid** — pipeline core is deterministic; outer wrapping (timestamps, random IDs) is non-deterministic but explicitly marked as such.

**What it affects:** Claim 4 (independent verification) directly. Non-determinism in the pipeline means a verifier can validate a single receipt's signature but cannot validate that the receipt was the one that *would have been* issued under those conditions.

### V.7 — Receipt composability

A receipt attests one thing. There is no first-class way to express "this gate fired *because of* these other receipts." Capability grants reference earlier grants in free-text fields. Delegation chains reference parent grants by ID. Policy snapshots aren't referenced from gate receipts at all.

**What's missing:** A typed mechanism for cross-receipt references. An audit-chain query that follows reference graphs. A discipline that prefers structured references over free-text mention.

**Options:**
1. **Receipt references as a top-level field** — every receipt has `references: Vec<ReceiptRef>` where each `ReceiptRef` includes the cited receipt's hash + a tagged reason. Schema-level support.
2. **Receipt graph as a separate structure** — receipts remain leaf nodes; a separate `ReceiptGraph` document captures references. Lighter on receipt schema; heavier on tooling.
3. **Status quo with discipline** — keep free-text, add a discipline that requires references to be receipt hashes (parsed and validated).

**What it affects:** Cognitive accountability (the Layer 3 trace vision in `docs/future-work/cognitive-accountability.md`). Without composability, "why did this gate fire?" requires reading prose, not following a graph.

---

## Part VI — Seam catalog re-map

Walking the existing seam catalog under the corrected frame.

### Closed (May 2026) — survive the pivot unchanged

These are substrate-internal seams. The new frame does not affect them.

- **Seam 1** — Audit chain signing.
- **Seam 2** — Gate parser.
- **Seam 3** — Fleet/node identity authentication (TOFU).
- **Seam 5** — Singular `verify_signature` helper.
- **Seam 8** — Announce replay protection (both paths).
- **Seam 9a** — Argv-form tool launch.
- **Seam 10** — Public-page supply chain (SRI).
- **Seam 11** — Test/production identity isolation.
- **Seam 17** — Canonical JSON helper.
- **Seam 19** — Path resolution unified.
- **Seam 20** — Hash-then-sign discipline.

### Open / partial — relevant but reshaped

- **Seam 4** — Receipt generation authority. Becomes part of the verb-set design: which agents are authorized to invoke which verbs. Likely subsumes Seam 4 entirely once the verb set lands.
- **Seam 12** — Configuration provenance. Rehabilitated. The CLI delivery still needs config provenance; `ConfigResolver` as the singular env-var carrier remains correct. The half-finished schema additions in the working tree are pointed in the right direction; what changes is fewer *handlers* to refactor.
- **Seam 13** — Error-type boundary discipline. Survives unchanged. Becomes more important under the verb-set frame because errors are typed responses, not free-form panics.
- **Seam 14** — Versioned-format dispatch. Mostly subsumed by the verb-set schema versioning. Receipt format versioning remains relevant; HTTP/JSON wire versioning evaporates because the wire is gone.
- **Seam 15** — Async cancellation. Survives unchanged.
- **Seam 16** — Receipt-actor key registry. Survives; verb-set design will inform the registry's shape.
- **Seam 18** — Newtype identifiers. Survives unchanged.

### Collapsed — go away under the new frame

- **Seam 9b** — Token plumbing via postMessage handshake. Collapses to zero for pixel-streamed delivery (no client-side context for a token to leak into). Resurrects only if a future browser-side delivery is introduced; deferred indefinitely.
- **Most of the 109 HTTP routes** — replaced by the verb set.

### New / pending

- **Seam 22** — API surface discipline (typed verb set; plural deliveries). The corrected frame. See `docs/STRUCTURAL-AUDIT-2026-05.md` for the full entry.

---

## Part VII — Open architectural questions

Each of these needs a decision but does not need it tonight. Options + trade-offs only; no recommendations forced.

### VII.1 — Pixel-streaming tech  ✅ Resolved (May 8 2026, see Part II.9)

**Decision:** WebRTC + Selkies-GStreamer as primary (zero-install browser path; production-tested at Google Cloud Workstations; cross-cutting overlap with libp2p WebRTC transport and verb data channels). Sunshine + Moonlight as secondary for latency-priority operators willing to install the Moonlight client. Neko, Apache Guacamole, noVNC, xpra not adopted (architectural mismatches or quality regressions). See Part II.9 and the Category D survey output in `docs/TECH-LANDSCAPE-2026-05.md`.

WebRTC + Selkies-GStreamer vs. Sunshine + Moonlight vs. Apache Guacamole vs. noVNC + custom signaling.

| Option | Pro | Con |
|---|---|---|
| WebRTC + Selkies | Universal browser; production at Google Cloud Workstations | Linux-only server side; GStreamer learning curve |
| WebRTC + Neko | Self-hostable; simpler ops | Designed for browser-in-container; layers may add up |
| Sunshine + Moonlight | Best latency/quality | Requires Moonlight client install (not browser-only) |
| Apache Guacamole | Simplest architecture, pure HTML5 | Lower video quality, designed for office not motion |
| noVNC | Pure browser, simple | Older framing; more bandwidth; higher latency |

**Recommendation pending user input.** Default lean if forced: WebRTC + Selkies for the zero-install property.

### VII.2 — gRPC adoption for the SDK boundary  ✅ Resolved (May 8 2026, see Part II.7 and II.8)

**Decision:** Adopt protobuf as the verb-set schema layer (Part II.7) — this is the dominant value, independent of transport. Adopt gRPC + tonic for the SDK boundary (Part II.8) — the natural transport for that contract. ConnectRPC adoption deferred until concrete browser-resident SDK consumers exist. msgpack envelopes remain on the mesh wire. See Part II.7, II.8, and the Category A survey output.

Adopt gRPC + protobuf for the SDK delivery, or stick with msgpack envelopes.

| Option | Pro | Con |
|---|---|---|
| gRPC + protobuf | Typed bindings for free across languages; the schema becomes the contract | protoc, codegen, multi-language client crates |
| Msgpack envelopes | Already disciplined; lighter tooling | SDK consumers hand-roll types |

The verb set could be defined in `.proto` regardless — used as the schema source for both gRPC and the mesh envelope codegen. That's a third option that gets the typed-contract win without committing to gRPC as the only SDK transport.

### VII.3 — Reads as receipts vs. typed-but-unsigned envelopes  ✅ Resolved (May 8 2026, see Part II.0 and Part III)

**Decision:** Reframe under Principle II.0 (contracts singular, implementations plural). The verb-set schema (a *port*) declares a per-verb response category — one of three:

- **Plain envelope** — typed data, no signature. For observation (`Health`, `Stats`, frequently-polled state).
- **Signed envelope** — typed data + node signature, not chained. For attestable answers that drive downstream commitments (`ChainHead`, `TrustTier`, `Identity`).
- **Full receipt** — signed and chained. For state-changing events (`Evaluate`, `Grant`, `Withdraw`, `AuditVerify`).

The schema is singular (every verb declares exactly one category). The categorization is plural (different verbs across the schema have different categories). Discipline pin enforces:

- Plain-envelope verb handlers may not write to the chain.
- Signed-envelope verb handlers must sign but may not chain.
- Full-receipt verb handlers must both sign and chain.

The earlier framing ("pick one — do reads produce receipts or not?") was a contract-vs-implementation category error. The verb set as a *port* admits all three response categories; per-verb declaration is part of the port's specification.

**Composition with deliveries:** in-process delivery (4.1) may *short-circuit* signing for `Signed*` types where the trust boundary is collapsed (function call from a trusted local process). Other deliveries honor the schema's full attestation. The schema declares the *upper bound* of attestation; specific adapters may relax it where their trust model makes the attestation redundant; adapters may never strengthen it beyond the schema's declaration.

### VII.4 — One-shape-everywhere vs. local/remote split  ✅ Resolved (May 8 2026, see Part II.0)

**Decision:** Reframe under Principle II.0. The dashboard UI is itself a *port* (one UI codebase, one user-facing contract); the deliveries that render and transport it are *adapters* (plural, per operator class). Today's first-class adapters:

- **4.1** — Native in-process (operator on same machine).
- **4.2** — Pixel-streamed via WebRTC (operator on different device with good connectivity).

Adding adapters in the future (e.g. Sunshine + Moonlight for latency-priority operators willing to install a client; a hypothetical mobile-native client; a TUI for SSH-only environments) is permitted under the principle, conditional on each new adapter justifying its existence by reference to a concrete operator class not adequately served by existing adapters.

The earlier framing ("pick one shape") was a contract-vs-implementation category error. The dashboard UI as a port admits multiple delivery adapters; the question was never which adapter is correct, but which adapters are first-class today and what justifies adding more.

**Counterbalance:** plurality is not sprawl. Discipline at this layer is per-instance justification — every adapter documents its operator class, the contract it adapts (the dashboard UI port), and the trade-offs that make it the right choice for that class. Removing an adapter requires showing no operator class still depends on it.

### VII.5 — Each of the remaining un-thought dimensions

V.1 (trust portability) and V.5 (anchoring threat model) resolved (May 8 2026, see Part II.12). Five dimensions still open:

- **V.2** — quorum sovereignty
- **V.3** — delegation withdrawal
- **V.4** — trust tier transitions
- **V.6** — pipeline determinism
- **V.7** — receipt composability

Each has the options listed in Part V; each needs a decision before code commits to a shape. The technology survey did not address these (categories I, J, K of Appendix C — quorum cryptography, subscription scale, agent observability — were out of scope for this survey).

### VII.6 — Which libp2p transports to enable  ✅ Resolved (May 8 2026, see Part II.10)

**Decision:** Default build enables QUIC + TCP + WebSocket + WebRTC. WebTransport deferred until Safari ships support. See Part II.10.

libp2p's transport list is itself plural: TCP, QUIC, WebRTC, WebSocket, WebTransport, and others. Each has different properties on encryption, latency, browser-reachability, NAT traversal, and operational complexity. We commit to libp2p (Part II.6); we don't commit to enabling every transport.

**Candidate primary set:**
- **QUIC** — encrypted by default, low-latency, multiplexed, the right modern primary.
- **WebSocket** — needed for browser-reachable nodes (when the dashboard pixel-stream needs out-of-band WebRTC signaling, or when an SDK consumer is browser-resident).
- **TCP** — fallback for environments where QUIC is firewalled (corporate networks, some ISPs).

**Candidate explicit-opt:**
- **WebRTC transport** — overlaps with delivery 4.2 (pixel-streaming uses WebRTC media tracks). If we adopt WebRTC for libp2p data channels too, we get cross-transport identity reuse for free; the cost is harder testing.
- **WebTransport** — HTTP/3-based, newer than WebSocket, less universally supported. Worth tracking but not adopting yet.

**Decision pending:** which of the above are enabled in the default build, vs. opt-in feature flags.

### VII.7 — gossipsub as a fourth subscription transport  ✅ Resolved (May 8 2026, see Part II.11)

**Decision:** Adopt gossipsub for the ZP-to-ZP subscription path of delivery 4.7. HTTP webhooks remain for non-ZP subscribers; Reticulum / mesh-envelope push for off-grid subscribers. The split is by subscriber class. See Part II.11.

Delivery 4.7 (subscription / outbound) currently lists three transports for the substrate's outbound push: HTTPS POST (classic webhook), Reticulum LXMF push, mesh envelope push. With libp2p committed, gossipsub becomes a fourth: a subscriber declares interest in a topic; the substrate publishes matching receipts to the topic; subscribers in the libp2p network receive them.

**Candidate decision:**
- **Adopt** — gossipsub is the natural fit for ZP-to-ZP subscriptions at internet scale.
- **Defer** — the existing three deliveries cover the cases we know about; adopt gossipsub when a concrete need emerges.

Probably "adopt" since gossipsub comes with the libp2p commitment essentially for free, but the surface area of subscription verbs may need to expand to express topic-based filters.

---

## Part VIII — What this document does NOT decide

To set explicit boundaries on what the regroup must produce versus what is already settled:

**This document does not decide:**
- The five remaining un-thought dimensions: V.2 quorum sovereignty, V.3 delegation withdrawal, V.4 trust-tier transitions, V.6 pipeline determinism, V.7 receipt composability.
- The exact verb set's shape (only that it exists, defined in protobuf, with a draft set in Appendix A and a per-verb response-category declaration per VII.3).
- The migration path from the 109-route HTTP API to the verb set.
- The timeline.

**This document does decide:**

*Meta-principle (May 8 2026):*
- Contracts are singular; implementations are plural (II.0). The substrate is hexagonal at every architectural seam.

*Foundational (May 7 2026):*
- Receipts are the typed boundary (II.1).
- Deliveries are plural (II.2).
- Reticulum compatibility is non-negotiable (II.3).
- The 109-route HTTP API as it stands retires (II.4).
- "Best part is no part" applies to *undisciplined* surfaces, not to capabilities (II.5).
- Both Reticulum and libp2p are committed peer stacks (II.6).

*Survey-driven (May 8 2026):*
- Protobuf is the verb-set schema layer (II.7).
- gRPC + tonic for the SDK boundary (II.8).
- WebRTC + Selkies-GStreamer for delivery 4.2 primary path (II.9).
- libp2p default transports: QUIC + TCP + WebSocket + WebRTC (II.10).
- gossipsub for ZP-to-ZP subscriptions (II.11).
- Trust portability + anchoring composition: OpenTimestamps + Bitswap + gossipsub, with an explicitly-stated threat model (II.12).

*Principle-driven (May 8 2026):*
- Verb-set responses come in three categories — plain envelope, signed envelope, full receipt — declared per-verb in the schema (VII.3, resolved under II.0).
- Dashboard UI is a port; its deliveries (4.1 native, 4.2 WebRTC, future adapters) are plural; new adapters require per-instance justification (VII.4, resolved under II.0).

**This document records as un-thought:**
- The five remaining dimensions in Part V (V.2, V.3, V.4, V.6, V.7).
- Each of which gets a section in a future document — or gets resolved during the verb-set design — but not in isolation as numbered seams.

---

## Appendix A — The v1 verb set

The verb set is real and on disk. See:

- **`proto/v1/common.proto`** — shared types (`ActorRef`, `Signature`, `ContentHash`, `ReceiptHeader`, `ReceiptKind`, `AuditEntry`, `PageRequest`, `ReceiptFilter`).
- **`proto/v1/guard.proto`** — Guard service (9 verbs): gate evaluation, proxy calls, policy module management, policy version control.
- **`proto/v1/delegation.proto`** — Delegation service (5 verbs): grant, delegate, verify-chain, renew-lease, get-credentials. (`WithdrawCapability` deferred pending V.3.)
- **`proto/v1/receipts.proto`** — Receipts service (6 verbs): generate, ingest, attestation issue/lookup/list, watch (streaming).
- **`proto/v1/audit.proto`** — Audit service (7 verbs): chain head, query entries, verify integrity, tail (streaming), reconstitute, get-latest-anchor, get-system-state.
- **`proto/v1/mesh.proto`** — Mesh service (11 verbs): announce, heartbeat, policy advertisement / proposal / vote / agreement, audit challenge / response / attestation, reputation broadcast, receipt-chain transfer.
- **`proto/v1/subscriptions.proto`** — Subscriptions service (4 verbs): subscribe, unsubscribe, list, register-channel-webhook. Targets are plural per Architecture II.11 (HTTP webhook, gossipsub topic, Reticulum address, mesh peer hash).
- **`proto/v1/nodestatus.proto`** — NodeStatus service (10 verbs): identity, stats, security posture, topology, blast-radius register/get, compromise report, fleet node list/get/deregister.

**Total: 7 services, 52 verbs across ~1,800 lines of proto.**

### Conventions applied (from Phase 3 design decisions, May 9 2026)

- **Naming:** verb-first with resource (`EvaluateGate`, `GrantCapability`, `GetChainHead`).
- **File layout:** per-service files in `proto/v1/`; common types in `proto/v1/common.proto`.
- **Service partitioning:** 7 services (Guard, Delegation, Receipts, Audit, Mesh, Subscriptions, NodeStatus).
- **Empty-input convention:** every verb has its own `<Verb>Request` message — no use of `google.protobuf.Empty`. Forward-compatible field addition.
- **Response category encoding** (per VII.3): type-name suffix.
  - `*Envelope` → plain envelope (no signature). Frequently-polled state; observation only.
  - `Signed*` → signed envelope (signed but not chained). Attestable answers driving downstream commitments.
  - `*Receipt` → full receipt (signed and chained). State-changing events.
  - Two carve-outs: `common.Receipt` (the canonical receipt type, used directly by `GenerateReceipt` / `IngestReceipt`) and `common.AuditEntry` (chain-bookkeeping wrapper used by `TailAuditEntries`).

### Reserved fields for future seams

The schema reserves two fields on `ReceiptHeader` for the un-thought dimensions:

- **`policy_snapshot_hash`** — Architecture II.12 trust-portability composition; populated when V.5 design lands.
- **`references`** — typed cross-receipt references; populated when V.7 (receipt composability) design lands.

Both are present in the schema but empty in v1 receipts. Adding them later is a non-breaking change because they're already declared.

### Infrastructure resources (allowlist, not verbs)

Per Architecture III, these HTTP paths stay as infrastructure resources and don't emit receipts:

- `GET /api/v1/health` — process supervisor / load balancer probe.
- `GET /api/v1/version` — version disclosure for compatibility checks.
- `GET /api/v1/events/stream` — SSE backing for `WatchReceipts` and `TailAuditEntries` streaming verbs.
- `POST /webrtc/signal` (to be added) — WebRTC SDP signaling for delivery 4.2 (pixel-streamed UI).
- `GET /assets/*` — static asset serving.

### Inventory of routes that retire

See `docs/VERB-SET-INVENTORY-2026-05.md` for the full list of ~44 HTTP routes that retire under the verb-set design. Categories: dashboard glue (replaced by delivery 4.1 / 4.2), dev-tools-only (feature-flagged, never ship), and duplicates (multiple HTTP paths collapsing into single verbs).

---

## Appendix B — Conversation history that produced this document

For the record, so future-Ken doesn't have to reconstruct the path from chat logs.

- **May 6, all day** — Tier-1 + Tier-2 invariantization sprint. Closed Seams 1, 3, 5, 8, 9a, 10, 11, 17, 19, 20.
- **May 7, morning** — Seam 12-B (configuration provenance) survey and partial implementation. Schema additions started in `crates/zp-config/src/schema.rs` (uncommitted in working tree).
- **May 7, mid-day** — Conversation about API patterns triggered by external context (video on REST/gRPC/GraphQL). Surveyed existing patterns: 109 HTTP routes, ad-hoc JSON shapes, WebSocket + SSE for streaming, msgpack envelopes on mesh. Honest assessment: HTTP API is undisciplined relative to substrate's claims.
- **May 7, afternoon** — Initial Seam 22 framing as "API surface discipline." Added Seam 21 (policy version attestation in receipts) and Seam 22 to audit doc. Seam 21 stripped same day on review (underspecified to be a numbered seam; concept moved into Seam 22's companion-work section).
- **May 7, late afternoon** — Pixel-streaming proposal as the "best part is no part" answer to dashboard discipline. Initial framing: "pixel-streaming for humans, receipts-only for agents."
- **May 7, late afternoon, immediately after** — Reticulum pushback. Pixel-streaming is structurally impossible for the off-grid operator class ZP is positioned for. Corrected framing landed: *typed verb set is the disciplined surface; deliveries are plural.*
- **May 7, evening** — This document drafted to capture the corrected frame, surface the un-thought dimensions, and re-map the seam catalog.
- **May 8, morning** — ZP commits to libp2p in addition to Reticulum (Part II.6). Architecture doc updated with the commitment and its sub-decision implications.
- **May 8, mid-morning** — Technology-landscape survey produced (`docs/TECH-LANDSCAPE-2026-05.md`) covering Appendix-C categories A (verb-set transports), C (streaming/subscription), D (pixel-streaming), G (audit/anchoring). Six load-bearing decisions recommended.
- **May 8, late morning** — Survey recommendations adopted as Part II decisions #7–#12. Part V.1 and V.5 closed; Part VII.1, VII.2, VII.6, VII.7 closed.
- **May 8, midday** — Stepping through VII.3 (response shapes) and VII.4 (dashboard delivery) surfaced the meta-principle that has been implicit across the architecture: **contracts are singular; implementations are plural** (port/adapter discipline applied recursively at every seam). Recorded as Part II.0. VII.3 and VII.4 resolved under the principle. Counterbalance stated explicitly: plurality at the implementation layer requires per-instance justification — adding adapters is deliberate; sprawl is forbidden by discipline. Five un-thought dimensions remain open (V.2, V.3, V.4, V.6, V.7).

---

## Appendix C — Technology landscape to survey

The May 7 conversation surfaced a recurring theme: a good portion of the architectural problems we've been hand-rolling solutions for have established, mature solutions in the wild. WebRTC is not a transport — it's a framework with media tracks, data channels, peer-to-peer NAT traversal, mandatory encryption, and identity assertions. WebSockets, webhooks, gRPC, SSE each fit naturally into the verb-set frame as different patterns we don't have to invent. Several of the un-thought dimensions in Part V have established prior art (OpenTimestamps for anchoring, FROST for threshold sovereignty, libp2p for non-Reticulum P2P, Sigstore Rekor for transparency logs).

The principle Ken named: **"why reinvent the wheel?"** — and its companion, **"the best part is no part — including no code I write that someone else already wrote correctly."**

The next session's work: a focused technology survey, organized by architectural concern, with notes on fit for ZP. The point is *not* to adopt everything, but to know what exists so leverage beats reinvention. The output of the survey lives in `docs/TECH-LANDSCAPE-2026-05.md` and feeds back into this architecture doc as decisions are made.

Categories to survey:

**A. Verb-set transports.** ✅ **Surveyed (May 8 2026):** Adopt protobuf as schema (Part II.7), gRPC + tonic as primary SDK transport (Part II.8). libp2p streams adopted via Part II.6/II.10. Mesh envelopes continue on Reticulum. Twirp, JSON-RPC (as primary contract), WebSocket framing as primary verb wire — not adopted. See `docs/TECH-LANDSCAPE-2026-05.md` for reasoning.

**B. Schema / IDL.** Protobuf, Cap'n Proto, FlatBuffers, MessagePack (existing), CBOR, JSON Schema. Differ on zero-copy, schema evolution, codegen ergonomics, and wire size.

**C. Streaming and subscription.** ✅ **Surveyed (May 8 2026):** gRPC server-streaming for typed streaming verbs; SSE for shell-friendly streaming in delivery 4.3; WebSocket as the duplex escape hatch; gossipsub for ZP-to-ZP subscriptions (Part II.11); HTTP webhooks for non-ZP subscribers. WebTransport tracked but not adopted (Safari support pending). NATS / MQTT not adopted. See survey doc.

**D. Pixel-streaming stacks.** ✅ **Surveyed (May 8 2026):** WebRTC + Selkies-GStreamer adopted as primary path (Part II.9). Sunshine + Moonlight as secondary for latency-priority operators willing to install a client. Neko, Apache Guacamole, noVNC, xpra not adopted. See survey doc.

**E. Native UI framework.** Tauri, iced, egui, Slint, Dioxus, Leptos, GTK4. Different trade-offs on platform support, idiomatic Rust, system-webview vs. pure-Rust rendering, and accessibility.

**F. P2P / mesh networking.** ✅ **Decided (May 8 2026):** ZP commits to *both* Reticulum (existing — radio mesh, low bandwidth, off-grid) and libp2p (internet-scale P2P, NAT traversal, peer routing) as first-class peer transports. See Part II.6. The substrate's mesh `Interface` abstraction accepts both; bridge nodes participating in both networks are first-class. Yggdrasil, Tailscale, Nebula, cjdns are *not* adopted — the two-stack commitment covers the spectrum. Sub-decisions remaining (transport selection within libp2p; gossipsub adoption) are tracked in Part VII.6 and VII.7.

**G. Audit and anchoring.** ✅ **Surveyed (May 8 2026):** OpenTimestamps adopted for chain-head anchoring; libp2p Bitswap + Kademlia DHT adopted for chain-segment retrieval (Part II.12). Composes with gossipsub (Part II.11) for live propagation. Full IPFS not adopted; underlying libp2p protocols are. Sigstore Rekor / CT / Trillian as reference designs only. See survey doc.

**H. Identity and authentication.** WebAuthn / passkeys (browser-supported, hardware-backed), PIV (smartcard standard, common in enterprise), Sigstore (keyless code signing via OIDC), FIDO2. The sovereignty provider system already has hooks for hardware tokens; this category is what's available beyond what we've wired.

**I. Quorum and threshold cryptography.** FROST (threshold Ed25519, the right primitive given ZP already uses Ed25519), Shamir Secret Sharing libraries, multi-sig wallet patterns. V.2 (quorum sovereignty) lives here.

**J. Subscription delivery infrastructure.** NATS JetStream, Apache Kafka, RabbitMQ, AWS SNS. Delivery 4.7 needs durable subscriptions and retry logic; battle-tested options exist.

**K. Tracing and provenance for ML/agent observability.** Adjacent to the cognitive accountability vision — LARQL (referenced in `CLAUDE.md`), MEDS, OpenTelemetry, distributed tracing standards. Forward-looking, not immediate.

**Output format for each category:** the relevant technologies, what concerns each addresses, honest fit assessment for ZP, and a recommended status — *adopt* (pull in immediately), *consider* (worth a deeper look before committing), or *avoid* (incompatible with our constraints, with reasons).

The survey is the natural prerequisite to drafting `proto/zp_v1.proto` (the verb set as a typed schema) and to making the open architectural calls in Part VII.

---

## Appendix D — Pencilled-in horizons

Not on any task list, not architectural commitment, not driving any near-term work — but worth recording so the analysis isn't lost when the topic resurfaces. These are feature classes that fit ZP's substrate naturally but are premature today.

### LLM Wiki — receipt-native knowledge layer

The "LLM Wiki" pattern (Karpathy's framing; popularized in mid-2026 tutorials) describes an AI agent that ingests sources once and maintains an interlinked, persistent knowledge base — rather than re-searching raw documents per query. Three layers: raw sources, AI-generated wiki pages, schema defining ingestion + linking + lint behavior.

**Why it fits ZP's horizon.** The pattern shape is the same as ZP's substrate-at-the-cognition-layer story: persistent state, structural relationships, lint-as-discipline. The natural ZP rendering: each wiki page is a receipt (or small receipt chain) referencing source receipts and other page receipts; the markdown view is a materialization, not the source of truth; lint rules are policy gates that emit receipts on violation; the operator's knowledge graph inherits ZP's chain integrity, actor attribution, and tamper detection. The receipt format already does what the markdown layer would do — but with structural trust the markdown can't carry on its own.

**Why it's premature today.** Two prerequisites. (1) The verb-set must be drafted enough to define ingestion / page-creation / cross-reference verbs — building the wiki before that means inventing schema the verb-set work would re-invent. (2) V.7 (receipt composability — `Part V`) must be designed — wiki links *are* typed cross-receipt references; without that primitive the wiki has no structural way to express linkage.

**When to revisit.** When the V.7 design session opens, use the wiki feature as a primary informing use case — it forces the cross-receipt reference primitive to be expressive enough for real consumption rather than abstract. A first wiki MVP then becomes a natural concrete demonstration of ZP at the cognition layer, alongside the LARQL/MEDS Layer 3 vision (`docs/future-work/cognitive-accountability.md` and `CLAUDE.md` § "Intellectual Context & Adjacent Thinkers"). Together they form the cognition-layer story: LARQL decomposes what models *know*; MEDS characterizes how they *reason*; the wiki layer captures what they've *learned and where it came from*.

**Recursive observation.** ZP's own development workflow is using a primitive form of this pattern right now — `CLAUDE.md` is the schema, `docs/` is the wiki, today's architectural arc was wiki-maintenance work (discover structural inconsistencies, name meta-principles, ripple them through the doc graph). That's evidence the pattern holds at development scale; experience here informs what the operator-facing version should look like when it's time.

---

*End of draft. Not committed. Open for revision.*
