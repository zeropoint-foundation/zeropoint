# Technology Landscape Survey — May 2026

*Prerequisite to the open architectural decisions in `docs/ARCHITECTURE-2026-05.md` Part VII. Covers four categories from Appendix C: verb-set transports (A), streaming and subscription (C), pixel-streaming stacks (D), and audit/anchoring (G). Output drives the verb-set design (`proto/zp_v1.proto`-or-equivalent) and the libp2p adapter implementation.*

*Status: draft, working tree only. Decisions land in the architecture doc as they're made.*

---

## Frame and method

### Why this survey

The May 6–7 sprint surfaced that ZP has been hand-rolling solutions where established, mature technologies exist. The architecture doc commits to a *typed verb set* with *plural delivery mechanisms* — and several of those deliveries can either be invented from scratch, or built on solid prior art. The wrong call sets us up to maintain code we shouldn't be writing. The right call leverages tooling, protocols, and operational practice that have already been hardened by larger ecosystems.

Each entry in this survey assesses one technology against ZP's *specific* concerns. Generic pros-and-cons lists from upstream documentation are not useful; honest fit assessments are.

### Constraints inherited from the architecture commitments

The survey accepts these as load-bearing (Part II of `ARCHITECTURE-2026-05.md`):

1. **Receipts are the typed boundary.** Every transport must carry receipts cleanly. Anything that imposes its own response shape on receipt-issuing verbs is a non-starter.
2. **Plural deliveries.** No single transport needs to serve all six operator environments. Choosing differently per delivery is correct, not a failure.
3. **Reticulum + libp2p are committed peer stacks.** Not "candidates." Survey entries that overlap (e.g. WebRTC, which can be a libp2p transport *and* the pixel-streaming wire) are noted explicitly.
4. **The 109-route HTTP API retires.** The verb-set design replaces it; survey decisions feed the verb set's transport choices.

### How to read this doc

Each technology gets:

- **What it is** — one paragraph, technical not marketing.
- **What it addresses for ZP** — which Part IV delivery and/or Part VII open question it touches.
- **Fit assessment** — honest, including where it doesn't fit.
- **Cost** — operational, dependency, browser/platform support, learning curve.
- **Status** — *adopt* (pull in immediately), *consider* (worth a deeper look before committing), *avoid* (incompatible with our constraints, with reasons).
- **Composition notes** — where this tech composes with others in the survey, or with the libp2p / Reticulum commitments.

A cross-cutting observations section at the end surfaces compositions and conflicts that don't fit inside any single entry. A recommendations section maps survey output back to Part VII open questions.

---

## A — Verb-set transports

The verb set is the typed boundary; transports are how verb invocations and receipt responses get from caller to substrate to caller. The mesh wire (msgpack envelopes) already exists; this category surveys what else can carry the same verb set.

### A.1 — gRPC (with tonic for Rust)

**What it is.** Google's RPC framework. HTTP/2-based. Schema in protobuf (`.proto`); codegen produces typed clients and servers in many languages. Streaming primitives (server-streaming, client-streaming, bidirectional) are first-class. Browser support requires gRPC-Web (a proxy-based variant) or Connect (see A.2). Tonic is the canonical Rust implementation, mature and production-ready.

**What it addresses for ZP.** Delivery 4.6 (third-party agent SDK) — the typed schema becomes the contract; SDK clients in Rust/TS/Python/Go/Java codegen for free. Part VII.2 (gRPC adoption decision) is exactly this entry.

**Fit assessment.** Strong fit for the SDK boundary. The verb set as `.proto` definitions is *the* schema-first move; everything that needs typed bindings flows from that file. Streaming primitives match Part C natively (server-streaming for tail/watch verbs). The tooling overhead is the cost: protoc, codegen, multi-language client crates, schema versioning discipline. Mature ecosystem absorbs most of that cost.

**Cost.** Learning curve for protobuf / `.proto` is real but bounded. Tonic compiles fast in dev mode; release builds are slower. Browser-side: gRPC-Web requires a proxy (envoy or similar) to translate HTTP/2 frames to HTTP/1.1; ConnectRPC (A.2) avoids this friction.

**Status.** **Adopt**, conditional on the verb set being defined in `.proto`. The protobuf schema becomes the source of truth for response shapes regardless of whether tonic is the primary transport.

**Composition.** `.proto` is shared schema for both gRPC (over HTTP/2 or QUIC) AND can codegen into Rust types used over libp2p streams (A.7) or mesh envelopes (A.8). Adopting protobuf as the IDL is independent of adopting gRPC as the transport.

### A.2 — ConnectRPC (Connect)

**What it is.** Buf's protocol, designed as a friendlier gRPC. HTTP/1.1 *and* HTTP/2; gRPC-compatible on the wire when run over HTTP/2. Native browser support without a proxy. Same `.proto` schemas as gRPC. Connect-Go and Connect-Web are mature; Rust support is via `connect-rs` (less mature than tonic) or by using tonic with a Connect-compatible adapter.

**What it addresses for ZP.** Same as gRPC (delivery 4.6, Part VII.2) but with materially less friction for browser-resident SDK consumers. If the SDK course's JS target is a hard constraint, Connect dramatically simplifies the path.

**Fit assessment.** Connect's value proposition is "gRPC's typed contract without gRPC's browser pain." That's directly aligned with what we want for SDK consumers. The Rust side is less polished than tonic; using tonic for the server and Connect-Web for the JS client is a common hybrid pattern that works.

**Cost.** Slightly more complex than picking pure-gRPC because the Rust ecosystem isn't as unified. Cost of *not* adopting Connect: gRPC-Web's proxy requirement, which adds an operational dep.

**Status.** **Consider**. Strong if browser-resident SDK consumers are a priority; defer if they're not.

**Composition.** Same protobuf schemas as gRPC; can coexist with gRPC. Connect-over-HTTP/1.1 is simpler to deploy than gRPC-over-HTTP/2 in some constrained environments (e.g. CDNs that don't pass HTTP/2 cleanly).

### A.3 — Twirp

**What it is.** Twitch's RPC protocol. HTTP/1.1, JSON or protobuf wire format. Simpler than gRPC: no streaming, no bidirectional flow, request/response only. `twirp-rs` is the Rust implementation; less active than tonic but functional.

**What it addresses for ZP.** A simpler alternative for the SDK boundary if streaming isn't required. Most verb-set verbs are request/response; only tail/watch verbs (Part C) need streaming.

**Fit assessment.** Twirp is "gRPC without streaming or HTTP/2 friction." The lack of streaming is fatal for our streaming verbs (`TailEntries`, `WatchReceipts`). Adopting Twirp would force a parallel transport for streaming, which violates plurality-at-the-delivery-level (we'd need two SDK transports instead of one).

**Cost.** Operationally simple. Ecosystem smaller than gRPC's.

**Status.** **Avoid.** Twirp is a tempting simplification but the streaming gap forces complexity elsewhere. ConnectRPC (A.2) covers Twirp's "simpler than gRPC" niche while supporting streaming.

### A.4 — JSON-RPC

**What it is.** Old, simple, well-understood. Used by Ethereum nodes, Bitcoin Core, language servers (LSP). No typed schema beyond JSON. Method names + positional or named parameters. Batch requests supported. Streaming is awkward (typically WebSocket-wrapped).

**What it addresses for ZP.** Could be the wire format for delivery 4.3 (CLI over HTTP/SSH) if we don't want gRPC there.

**Fit assessment.** JSON-RPC's simplicity is genuinely valuable for a CLI delivery — no codegen, easy to invoke from any HTTP client, debuggable with `curl`. But it conflicts with the verb-set discipline: there's no schema layer enforcing that responses are receipts. We'd be reintroducing the "ad-hoc JSON shapes" problem at the SDK boundary unless we *manually* discipline JSON-RPC responses to always be receipts.

**Cost.** Zero learning curve. Zero codegen tooling. No typed bindings.

**Status.** **Avoid for the typed-contract boundary**. **Consider for the CLI delivery** if we want a wire that's invokable from any shell — but in that case, the CLI binary is the typed adapter and the JSON-RPC wire is just bytes between processes. The CLI itself uses the verb-set Rust types internally; the wire happens to be JSON-RPC. This is a defensible position for delivery 4.3 specifically.

**Composition.** Could ride alongside gRPC: gRPC for SDK consumers, JSON-RPC for shell-pipe-friendly CLI invocation. Same verb set, two wire formats. Cost: two serializers, slight risk of drift.

### A.5 — WebSocket framing

**What it is.** WebSocket as transport (HTTP-upgrade, persistent, duplex), with app-defined message format on top. Could carry msgpack, JSON, protobuf, or anything. `tokio-tungstenite` is already in our lockfile.

**What it addresses for ZP.** Already covered as a transport option for delivery 4.3 streaming patterns (Part IV.7 of the architecture doc). Not a *separate* transport — it's a wire choice for the existing delivery.

**Fit assessment.** Useful specifically for the streaming/duplex case in delivery 4.3. Not a candidate for the primary verb-invocation wire because it requires connection persistence (caller must hold a session); request/response is more naturally HTTP. WebSocket frames carrying gRPC or Connect are a thing (gRPC-Web does this), but adopting WebSocket as a primary verb transport when we already have gRPC over HTTP/2 is gratuitous.

**Cost.** Already in the build. Operationally cheap.

**Status.** **Adopt for streaming/duplex inside delivery 4.3** (matches Part IV.7's framing). **Avoid as a primary verb-transport.**

### A.6 — WebRTC data channels

**What it is.** WebRTC's bidirectional reliable-or-unreliable, ordered-or-unordered byte streams between peers. P2P with NAT traversal via STUN/TURN. Mandatory DTLS-SRTP encryption. SCTP under the hood. The data-channel API is general-purpose: any bytes between two peers, app-defined message format.

**What it addresses for ZP.** Two things:
1. **Delivery 4.2 augmentation** — pixel-streaming uses WebRTC media tracks for video; the same WebRTC connection can carry verb invocations on a data channel. Single connection, one auth handshake (signed SDP), two channels (media + verbs).
2. **libp2p WebRTC transport** — libp2p includes WebRTC as a peer transport (the `webrtc-direct` and `webrtc` modules in rust-libp2p). Adopting libp2p's WebRTC transport gives ZP a way to reach browser-resident peers that can't accept TCP/QUIC.

**Fit assessment.** Strong fit if pixel-streaming is delivery 4.2's chosen tech (Part VII.1). Reusing the WebRTC connection for verb traffic eliminates a parallel auth path. Strong fit also as a libp2p transport for browser peers. Cost: WebRTC's complexity is real — STUN/TURN servers, ICE negotiation, NAT-type sensitivity. Self-hosting STUN is trivial; TURN (when STUN fails) is operationally non-trivial.

**Cost.** Adding a TURN server to the deployment story is the main operational cost. The Rust WebRTC ecosystem (`webrtc-rs` crate) is mature enough; rust-libp2p's WebRTC transport handles much of the complexity.

**Status.** **Adopt** if pixel-streaming chooses WebRTC (probable per Part VII.1). **Adopt as libp2p transport** for browser-resident peers. The two adoptions reinforce each other.

**Composition.** WebRTC is the cross-category overlap point: pixel-streaming D, libp2p transport (Part II.6), and verb data channel A.6 all use the same primitive. Strong leverage for adopting it once.

### A.7 — libp2p streams

**What it is.** Multiplexed, named streams over any libp2p transport (TCP, QUIC, WebRTC, WebSocket, WebTransport). App-defined protocol — handlers register a multiaddr-style protocol ID (e.g. `/zp/verb/1.0.0`) and accept inbound streams matching that ID. Encryption (Noise or TLS 1.3) is mandatory at the libp2p layer; streams are carried over the secure session.

**What it addresses for ZP.** Delivery 4.6 (third-party agent SDK) for ZP-native peers. A libp2p-resident peer can invoke verbs over a libp2p stream rather than over gRPC. Comes "for free" with the libp2p commitment.

**Fit assessment.** Excellent fit for ZP-to-ZP verb invocation. Same transport stack as the rest of libp2p (gossipsub, content routing, peer discovery), so adding verb invocation requires only a new protocol-ID handler. Identity is already established via libp2p's PeerId — no separate auth.

**Cost.** Defining the wire format on top of streams (protobuf? msgpack? Length-prefixed framed gRPC over the stream?) is a design call. The simplest path is *gRPC over libp2p streams* — the protobuf schema does double duty for both gRPC-over-HTTP/2 (SDK boundary) and gRPC-over-libp2p (ZP-to-ZP). This composition is documented in libp2p literature and works in practice.

**Status.** **Adopt**, with the wire format decision (gRPC-framed bytes vs. raw protobuf vs. msgpack) deferred to the verb-set design.

**Composition.** Reuses the verb-set protobuf schema from A.1. Reuses libp2p's encryption and identity. Combines with content routing (G.4 / IPFS) for chain-segment retrieval.

### A.8 — Mesh envelopes (existing, msgpack)

**What it is.** ZP's existing wire format in `crates/zp-mesh/src/envelope.rs`. Msgpack-encoded structures, tagged by `EnvelopeType` (17 variants), typically 150–300 bytes. Designed for radio-bandwidth efficiency; works over Reticulum and any other low-bandwidth transport.

**What it addresses for ZP.** Delivery 4.4 (Reticulum / radio mesh) and the agent-side of delivery 4.6 over mesh. Already disciplined; not under question.

**Fit assessment.** Optimal for Reticulum-class environments. Wrong shape for high-bandwidth gRPC-style streaming; we don't need it to be that shape there.

**Cost.** Already in the build. Maintenance cost is bounded.

**Status.** **Adopt — already adopted.** Continues as-is for Reticulum; complemented by gRPC/libp2p streams for higher-bandwidth deliveries.

**Composition.** Could theoretically be replaced by `protobuf-over-msgpack` if we want a unified schema across mesh and gRPC. Not urgent; current shape is fine.

### Category A synthesis

The clean shape: **protobuf as the schema layer; multiple wire transports underneath.** Verb set defined in `.proto`. Transports: gRPC-over-HTTP/2 for SDK consumers (with optional Connect for browsers), gRPC-over-libp2p for ZP-to-ZP, msgpack envelopes over Reticulum for low-bandwidth peers, JSON-RPC for shell-friendly CLI invocation. Same verb set everywhere; different wires per environment. WebSocket is an internal-to-delivery-4.3 streaming option, not a primary transport.

---

## C — Streaming and subscription

Delivery 4.7 (subscription / outbound) and the streaming verbs (`TailEntries`, `WatchReceipts`, etc.) need to be carried by *some* mechanism. This category surveys the candidates.

### C.1 — gRPC server-streaming

**What it is.** gRPC's `stream T` response type. Server holds the stream open; emits messages until the client cancels or the server ends the stream. HTTP/2-multiplexed; multiple streams ride one connection. Tonic supports it natively.

**What it addresses for ZP.** Streaming response verbs (Pattern A in Part IV.7). Naturally typed via the same `.proto` that defines the verb set.

**Fit assessment.** Best-fit for typed streaming. No format mismatch with non-streaming verbs — a `WatchReceipts(filter) returns (stream Receipt)` signature is as much "the schema" as `Evaluate(req) returns (GuardReceipt)`.

**Cost.** None beyond gRPC adoption (A.1).

**Status.** **Adopt**, conditional on gRPC adoption (A.1).

**Composition.** Strong with libp2p streams (A.7) — gRPC-over-libp2p inherits gRPC streaming semantics.

### C.2 — Server-Sent Events (SSE)

**What it is.** HTTP-native one-way stream. `Content-Type: text/event-stream`. Server writes `data: ...\n\n` framed messages; browser `EventSource` API consumes them. Reconnects automatically on disconnect with `Last-Event-ID`. One-way only (server → client); requests still go via standard HTTP.

**What it addresses for ZP.** Streaming for delivery 4.3 (CLI over HTTP/SSH) and dashboard's existing `/api/v1/events/stream`. Already used in `crates/zp-server/src/events.rs`.

**Fit assessment.** Useful for shell pipelines (`curl -N` consumes SSE cleanly), simpler than WebSocket, no upgrade handshake. Limitation: one-way. Streaming verbs that need request-time parameters use a separate POST then subscribe to the SSE stream — workable but two-step. Auto-reconnect is a real benefit for flaky connections.

**Cost.** Already in the build (axum's `Sse` response type). Operationally cheap.

**Status.** **Adopt** for streaming inside delivery 4.3, as a complement to gRPC streaming for non-gRPC clients.

**Composition.** SSE wraps any byte payload; if payload is a serialized receipt (canonical JSON or msgpack), discipline is preserved.

### C.3 — WebSocket as streaming/subscription transport

**What it is.** Already covered in A.5; restated here as a streaming/subscription transport. Duplex; persistent; framed.

**What it addresses for ZP.** Same as A.5 — streaming/duplex within delivery 4.3 when SSE's one-way limitation is too constraining.

**Fit assessment.** Fits where the operator needs to send messages mid-stream (e.g. modify the filter on an active subscription). For pure tail-the-stream patterns, SSE is simpler.

**Cost.** Already in the build.

**Status.** **Adopt** for duplex streaming patterns in delivery 4.3. **Defer** as the default — start with SSE, escalate to WebSocket only when bidirectional is genuinely needed.

### C.4 — WebTransport

**What it is.** HTTP/3-based transport. Streams + datagrams. Designed as WebSocket's modern successor: lower overhead, multiple streams without head-of-line blocking, native browser API. Browser support: Chrome/Edge full (since Chrome 97), Firefox added support in v114 (early 2023), Safari in development as of mid-2025.

**What it addresses for ZP.** Future replacement for WebSocket in delivery 4.3 streaming.

**Fit assessment.** Architecturally the right shape — no HoL blocking, datagrams alongside streams, designed for modern web. But Safari's lag means we can't adopt it as the only browser-side streaming option without losing Safari users. WebSocket remains the universal fallback.

**Cost.** Adding a second streaming wire (WebSocket + WebTransport) doubles surface area for marginal benefit until Safari support lands.

**Status.** **Track**, neither adopt nor avoid. Revisit when Safari ships WebTransport. Until then, WebSocket is the universal browser streaming wire.

**Composition.** libp2p has a WebTransport transport (`libp2p-webtransport-websys` for browser, server-side via `libp2p-webtransport`). Adopting WebTransport for libp2p is independent of adopting it for the verb-set transport.

### C.5 — gossipsub (libp2p)

**What it is.** libp2p's pub-sub protocol. Mesh-based: peers form a partial mesh per topic, gossip messages flood the mesh with damped redundancy. Designed at scale by Ethereum Foundation; Filecoin and other production systems run on it. Topics are arbitrary strings; messages are arbitrary bytes.

**What it addresses for ZP.** Delivery 4.7 (subscription / outbound) for ZP-to-ZP subscribers. Operator subscribes to a gossipsub topic (`/zp/receipts/v1/<filter>`), the substrate publishes matching receipts to the topic, all mesh-resident subscribers receive.

**Fit assessment.** Excellent. Comes free with libp2p commitment (Part II.6). Solves the multi-subscriber receipt-fan-out problem natively. Properties: at-most-once delivery (messages can be lost, mitigated by retransmits and topic mesh redundancy); message ordering is per-publisher only; messages can be signed (gossipsub's `sign_message` option ensures provenance).

**Cost.** Configuration tuning (mesh size, heartbeat interval, message cache duration) is non-trivial but documented. No additional dependency beyond libp2p.

**Status.** **Adopt** for the ZP-to-ZP subscription case. **Webhooks remain** for non-ZP subscribers (delivery 4.7 over HTTP).

**Composition.** Topic naming convention should encode filter shape so subscribers can declare interest precisely. Receipts published to topics retain their signatures; gossipsub provides delivery, the receipt provides trust.

### C.6 — NATS (and JetStream)

**What it is.** Lightweight pub-sub messaging server. Wire protocol is simple text-based commands. JetStream adds persistence, exactly-once delivery, and stream replay. Used heavily in cloud-native ecosystems (CNCF). Single Go binary; clusterable.

**What it addresses for ZP.** Subscription delivery infrastructure for the webhook case (delivery 4.7). NATS could be the durable subscription store and retry layer between substrate and external subscribers.

**Fit assessment.** Strong fit for *operating a webhook delivery service at scale*. Less needed for a single-node ZP that's pushing webhooks directly. The decision point: are webhooks a ZP-internal concern (substrate POSTs to subscriber's URL directly) or a separate-service concern (substrate publishes to NATS, NATS handles retries and fan-out)?

**Cost.** Adds a NATS server to the deployment. Only justified if webhook scale demands it — for low subscriber counts, direct HTTP POST with retry-in-substrate is simpler.

**Status.** **Avoid for v1.** **Consider for scale** if webhook subscribers ever reach hundreds-plus or if cross-substrate event distribution becomes a thing.

**Composition.** NATS could serve as inter-substrate event distribution if multiple ZP nodes need to share subscription fanout. gossipsub (C.5) covers this for ZP-native peers; NATS would cover the mixed-deployment case.

### C.7 — MQTT

**What it is.** Pub-sub for IoT and constrained devices. Low overhead, designed for unreliable networks. Brokers: Mosquitto (open source), EMQX, HiveMQ. QoS levels (0/1/2) for delivery guarantees.

**What it addresses for ZP.** Subscription delivery for IoT-class subscribers — embedded devices that need to receive notifications but can't run libp2p or HTTP.

**Fit assessment.** Niche. ZP's IoT story is via Reticulum (delivery 4.4), not MQTT. Adding MQTT would be a third subscription transport; adoption only justified if a real subscriber class needs it.

**Cost.** Broker dependency.

**Status.** **Avoid** for v1. Reticulum (existing) covers the IoT-shaped scenarios ZP positions for; MQTT would be a parallel path without clear additional value.

### Category C synthesis

Clean shape: **gRPC streaming for typed streaming verbs**, **SSE for shell-friendly streaming in delivery 4.3**, **WebSocket as the duplex escape hatch**, **gossipsub for ZP-to-ZP subscriptions**, **HTTP webhook (delivery 4.7) for non-ZP subscribers**. Avoid NATS/MQTT/WebTransport for v1. Each transport has a clear lane; no overlap fights.

---

## D — Pixel-streaming stacks

Delivery 4.2 needs to render a native UI server-side and stream it to a browser (or thin native client). This category surveys the candidates.

### D.1 — WebRTC + Selkies-GStreamer

**What it is.** Selkies-GStreamer is a Linux server-side stack: GStreamer pipeline captures a virtual X display, encodes via NVENC (NVIDIA), VAAPI (Intel/AMD), or software, packages into WebRTC media tracks. Browser receives via standard WebRTC. Used in production at Google Cloud Workstations.

**What it addresses for ZP.** Delivery 4.2 (pixel-streamed remote UI) for browser clients on Linux servers.

**Fit assessment.** Strong fit when the ZP server is Linux — covers most production deployments. NVENC support is hardware-accelerated and high-quality; VAAPI is solid for Intel/AMD; software fallback is universal. WebRTC is the right transport (browser-native, no client install).

**Cost.** GStreamer pipeline complexity is real — debugging encoder/transport issues requires GStreamer literacy. Not Mac/Windows-server compatible (Selkies is Linux-only). Operational cost: TURN server for non-LAN connections.

**Status.** **Adopt** for Linux-server deployments. Pair with one of D.3 / D.4 for Mac/Windows-server deployments (if those are in scope).

**Composition.** WebRTC overlap with A.6 (data channel for verb invocation) and libp2p WebRTC transport — same primitive serves three purposes; strong leverage.

### D.2 — WebRTC + Neko

**What it is.** BSD-3-licensed, Docker-based virtual browser streaming. Designed primarily for "browser-in-container" use cases (collaborative browsing, sandboxed browsing) but the streaming layer is general-purpose. Self-hostable, no external dependencies.

**What it addresses for ZP.** Same as D.1, with simpler ops at the cost of architectural fit.

**Fit assessment.** Neko is designed around X applications running inside the container. Adapting it to stream a ZP-native dashboard is workable but adds a layer (run the dashboard in a containerized X session, then Neko streams the X session) versus Selkies's more direct framebuffer-to-WebRTC path.

**Cost.** Docker dependency. Container running an X session is more layers than ZP's deployment story currently has.

**Status.** **Avoid** unless the simpler-ops story significantly outweighs the architectural overhead. Selkies (D.1) is the cleaner path.

### D.3 — Sunshine + Moonlight

**What it is.** Sunshine: open-source game-streaming server (GPL, LizardByte org). Moonlight: open-source client. Mature; designed for low-latency gaming. Hardware encoder support: NVENC, QSV (Intel), VAAPI, VideoToolbox (Mac), AMF (AMD). Cross-platform server (Linux/Mac/Windows). Custom protocol (NVIDIA GameStream-derived); not browser-native.

**What it addresses for ZP.** Delivery 4.2 with the lowest-latency profile available. Excellent quality. Cross-platform server.

**Fit assessment.** Best technical fit for sub-50ms input-to-glass latency. The cost is real: requires Moonlight client install (not browser-only). For the operator who values latency over zero-install, Sunshine is the right pick. For the operator who can't install custom software (corporate-managed laptops, etc.), it's a non-starter.

**Cost.** Client install on every operator device. Sunshine's GPL license requires careful linkage if we redistribute or wrap.

**Status.** **Consider** as a secondary option for operators who prioritize latency. **Avoid as primary** because zero-install is the better default for the broad operator class.

**Composition.** Doesn't compose with libp2p or WebRTC (uses its own protocol). Standalone delivery option.

### D.4 — Apache Guacamole

**What it is.** Clientless remote desktop gateway. Server-side: a Guacamole server speaks RDP, VNC, and SSH backends. Client-side: pure HTML5 + WebSocket; no plugin or installation. Mature (Apache project, decade-plus history).

**What it addresses for ZP.** Delivery 4.2 with the simplest browser story.

**Fit assessment.** Architectural mismatch: Guacamole expects an RDP/VNC source. Wrapping ZP's native dashboard in a VNC server (e.g. `Xvnc` running the dashboard, Guacamole streaming it) adds layers. Quality is lower than WebRTC-native paths because VNC framing is older. For office-work-shaped use cases (dashboards, forms), good enough; for motion-heavy content, visibly worse.

**Cost.** Java dependency (Guacamole server is Java). VNC/RDP backend dependency.

**Status.** **Avoid.** Selkies (D.1) is browser-clientless and architecturally cleaner.

### D.5 — noVNC + custom signaling

**What it is.** Pure-browser VNC client. Speaks VNC protocol over WebSocket. Simple deployment: serve noVNC's static files alongside a WebSocket-to-VNC bridge.

**What it addresses for ZP.** Delivery 4.2 with the absolute simplest implementation.

**Fit assessment.** VNC's framing is pre-h.264 era; bandwidth and latency are noticeably worse than WebRTC-native paths. The simplicity is real but the user-experience cost is significant.

**Cost.** VNC server dependency (or `Xvnc` running the dashboard). WebSocket-to-VNC bridge (websockify or similar).

**Status.** **Avoid.** The simplicity-vs-quality trade-off is wrong for an operator dashboard.

### D.6 — xpra HTML5

**What it is.** xpra ("screen for X") streams individual X applications (not full desktops) over a WebSocket-based HTML5 client. Niche; less polished than the WebRTC-based options.

**What it addresses for ZP.** Delivery 4.2 if we want application-level streaming rather than framebuffer-level.

**Fit assessment.** Application-level streaming is interesting but doesn't match how a native dashboard is structured (the dashboard is one application, not a set of windows we want to stream individually). The HTML5 client's polish is below WebRTC alternatives.

**Cost.** xpra dependency, X server dependency.

**Status.** **Avoid.**

### Category D synthesis

Clean shape: **Selkies-GStreamer over WebRTC** as the primary delivery 4.2 stack. Sunshine + Moonlight as a secondary option for latency-prioritizing operators willing to install a client. Everything else (Neko, Guacamole, noVNC, xpra) is an architectural mismatch or quality regression. WebRTC's overlap with libp2p (A.6) and the verb data-channel (A.6) means adopting Selkies + WebRTC pulls double or triple duty.

---

## G — Audit and anchoring

Two related but distinct concerns: anchoring (proving "this state existed at this time" via an external trusted source) and trust portability (V.1 — making chain segments retrievable across systems). Both touch G's surveyed technologies.

### G.1 — OpenTimestamps

**What it is.** Bitcoin-based timestamp anchoring service. Client computes a hash of the data to be timestamped; the OpenTimestamps server aggregates many such hashes into a Merkle tree; the tree's root is committed to a Bitcoin transaction periodically (typically every few minutes to hours). Verification: anyone with the Bitcoin blockchain can verify the hash was committed at the timestamped block. No need to run a Bitcoin node; the proof file is self-contained. Mature (since 2016).

**What it addresses for ZP.** V.5 (anchoring threat model). Anchoring the audit chain's head hash to Bitcoin via OpenTimestamps proves "the chain at this state existed by this time." Defends against retroactive chain rewrites — an attacker who forges a chain segment cannot also forge the Bitcoin commitment that timestamped the original.

**Fit assessment.** Lightweight, low-cost (free), well-understood threat model. Limitation: timestamp granularity is coarse (Bitcoin block time, ~10 minutes); not suitable for high-frequency anchoring. Fit for ZP: anchor the chain head hourly or daily; use it to defend against long-range rewrites, not for fine-grained replay protection (which the chain's own structure handles).

**Cost.** Network access during anchoring; otherwise free. The OpenTimestamps server is run by the project; self-hosting is possible but unnecessary for most use.

**Status.** **Adopt** for V.5. Provides exactly the property "this chain state existed by time T" that anchoring is supposed to give.

**Composition.** Composes with the audit chain directly: append a `ChainAnchor` event to the chain that contains the OpenTimestamps proof for an earlier chain head. The proof file itself becomes part of the chain.

### G.2 — Sigstore Rekor

**What it is.** Append-only transparency log used by Sigstore for code signing. Rekor servers publish a verifiable log; clients can prove inclusion of a record via Merkle proofs. Designed by the OpenSSF; production-deployed (the public Rekor instance handles millions of entries). Self-hostable via Trillian (G.4).

**What it addresses for ZP.** V.5 (anchoring) at higher granularity than OpenTimestamps. Receipts could be logged to Rekor; verifiers prove a receipt was published in the public log.

**Fit assessment.** Strong fit for *transparency* (anyone can audit the log) but adds a public dependency and external service. ZP's audit chain is *already* an append-only log; logging to Rekor is duplicative unless we want public auditability of the chain head specifically.

**Cost.** Public Rekor is free but not infrastructure we control. Self-hosted Rekor (via Trillian) is operationally non-trivial.

**Status.** **Consider for public auditability** if that becomes a requirement. **Avoid for v1** — OpenTimestamps (G.1) provides the anchor-against-rewrites property at lower operational cost.

**Composition.** If adopted, Rekor logs the chain head (or specific receipts); clients fetch inclusion proofs to verify.

### G.3 — Certificate Transparency (CT)

**What it is.** The original transparency log pattern, used by Google for HTTPS certificate monitoring since 2013. Open standard (RFC 6962). Multiple log operators run CT logs; browsers require CT inclusion for new HTTPS certs. Trillian is the reference implementation.

**What it addresses for ZP.** V.5 by analogy; not directly applicable since ZP's data isn't TLS certificates.

**Fit assessment.** CT's *pattern* (append-only log, Merkle proofs, public verifiability) is what Rekor (G.2) and ZP's audit chain both implement. CT itself is wrong-shaped for ZP's use case.

**Status.** **Avoid as direct dependency.** **Reference for design patterns** — the CT design (Merkle tree of leaves, signed tree heads, inclusion + consistency proofs) is the mature reference for any transparency-log-shaped feature ZP adds.

### G.4 — Trillian

**What it is.** Google's verifiable log infrastructure. Production-deployed for CT, Sigstore Rekor, and others. Append-only, Merkle-tree-backed log with a defined consistency protocol.

**What it addresses for ZP.** Backend for self-hosted Rekor or CT-style logs.

**Fit assessment.** ZP's audit chain is already a verifiable log; reimplementing on top of Trillian would replace existing code rather than add capability. Direct adoption isn't justified.

**Status.** **Avoid as direct dependency.** **Reference for the chain design** — the Merkle proofs, consistency proofs, and signed tree heads in Trillian are the canonical implementation; ZP's audit chain should match the algorithmic shape.

### G.5 — IPFS (InterPlanetary File System)

**What it is.** Content-addressed distributed storage. Files are addressed by hash (CIDs). Built on libp2p. Bitswap protocol for retrieval; DHT for discovery. The flagship application of libp2p.

**What it addresses for ZP.** V.1 (trust portability). Chain segments are content-addressable; IPFS's libp2p-based discovery + Bitswap retrieval gives V.1 a concrete mechanism. Pin chain segments to IPFS; verifiers retrieve segments by hash from any peer that has them.

**Fit assessment.** Strong fit for V.1 because:
1. ZP already commits to libp2p (Part II.6); IPFS adds content routing on top of libp2p we already have.
2. Chain segments are naturally content-addressed (each segment has a hash).
3. The "verifier wants chain context to verify a receipt" use case maps directly to "fetch hash X from any peer that has it."

The full IPFS stack (kubo, the Go reference implementation) is heavyweight. The relevant *protocols* (Bitswap, DHT-based peer routing for content) are available as libp2p sub-protocols without bringing in all of IPFS.

**Cost.** Adopting Bitswap-on-libp2p as a protocol is light. Adopting full IPFS as a system is heavy and probably wrong.

**Status.** **Adopt the protocols** (Bitswap, content routing via Kademlia DHT) as part of the libp2p stack. **Avoid the full IPFS stack** (kubo, IPLD, etc.) as a dependency.

**Composition.** This is the core mechanism for V.1 (trust portability). Combined with audit-chain hash-linked structure: any chain segment is a CID; libp2p discovers and retrieves it. Combined with OpenTimestamps (G.1): chain segments are anchored to Bitcoin and content-addressed via libp2p.

### Category G synthesis

Clean shape: **OpenTimestamps for anchoring** (cheap, well-defined threat model). **libp2p Bitswap + DHT for chain-segment retrieval** (free with libp2p commitment; gives V.1 a concrete mechanism). **Sigstore Rekor only if public auditability becomes a requirement.** **Trillian and CT as reference designs, not dependencies.** Full IPFS is overkill; the underlying protocols are right-sized.

---

## Cross-cutting observations

### Compositions that fall out for free

The libp2p commitment (Part II.6) brings several capabilities essentially without additional adoption cost:

- **Encrypted connections by default** (Noise / TLS 1.3) — same encryption discipline as TLS but at the libp2p layer.
- **Peer identity from public key** — PeerId is a hash of the Ed25519 public key; no separate identity management needed for libp2p peers.
- **Content routing via DHT** — chain-segment retrieval (V.1) becomes free.
- **Pub-sub via gossipsub** — subscription delivery (4.7) for ZP-to-ZP becomes free.
- **NAT traversal** — DCUtR + AutoNAT + hole-punching solve operator-behind-NAT scenarios.
- **Multi-transport** — TCP, QUIC, WebRTC, WebSocket, WebTransport are all available; we choose which to enable (Part VII.6).

This is the strongest argument for the libp2p commitment: a single dependency unlocks five-plus capabilities that would otherwise require building or integrating separately.

### WebRTC is the cross-category overlap point

WebRTC appears in three places: pixel-streaming (D.1), libp2p transport (Part VII.6 candidate), and verb-set data channels (A.6). Adopting it once serves all three. Architecturally:

- **Pixel-streaming**: WebRTC media tracks for video.
- **Verb invocation**: WebRTC data channel on the same connection.
- **Browser-resident peers**: libp2p over WebRTC transport.

The TURN server cost is paid once and serves all three. The signed-SDP authentication path is shared. The encoder hardware (NVENC/VAAPI/VideoToolbox) is shared. **Adopting WebRTC at this position has unusually high leverage.**

### Protobuf as the schema layer is independent of gRPC as the transport

Several entries (A.1, A.2, A.7) reference protobuf schemas. Adopting protobuf as the IDL is a *separate* decision from adopting gRPC as the transport. Even if we used gRPC only at the SDK boundary and used msgpack envelopes elsewhere, defining the verb set in `.proto` gives us:

- Generated typed Rust types for handlers.
- Generated SDK clients in TS/Python/Go.
- Versioning discipline (protobuf field numbering).
- A discipline-pin target ("every public response type must be defined in `.proto`").

This is the "schema as source of truth" property; the wire format underneath is an implementation detail.

### gossipsub vs. webhooks: the subscription split has a clean shape

Delivery 4.7 (subscription / outbound) currently lists three transports: HTTP webhook, Reticulum push, mesh envelope push. The libp2p commitment adds a fourth: gossipsub. The clean split:

- **gossipsub**: ZP-to-ZP subscriptions. Both publisher and subscriber are libp2p peers. Receipts published to topics; subscribers receive in the topic mesh.
- **HTTP webhook**: ZP-to-non-ZP subscribers (PagerDuty, Slack, monitoring). Substrate POSTs receipt-as-body to subscriber URL.
- **Reticulum push**: Off-grid subscribers reachable only via Reticulum.
- **Mesh envelope push**: Same as Reticulum but for non-Reticulum mesh peers.

These don't compete; each serves a different subscriber class.

### What's notably absent that might matter

- **Distributed tracing infrastructure** (OpenTelemetry, Jaeger, Tempo) — not surveyed because Category K (tracing) was forward-looking. But if we want Layer 3 cognitive accountability ever, OpenTelemetry's data model is worth knowing.
- **A formal verification layer for the verb set** — out of scope for this survey but worth flagging: tools like `protobuf-rs`, `validator-rs`, or schema-aware testing (model-based property tests) could enforce verb-set invariants at runtime. Adjacent to discipline pins but at a different layer.

---

## Recommendations mapped to Part VII open questions

Each Part VII question of `ARCHITECTURE-2026-05.md` gets a survey-supported answer. These are the survey's *recommendations*; the actual decisions land in the architecture doc when committed.

### VII.1 — Pixel-streaming tech

**Recommendation: WebRTC + Selkies-GStreamer as primary; Sunshine + Moonlight as secondary for latency-priority operators.**

Reasoning: Selkies is the zero-install browser path, production-tested, and reuses WebRTC with libp2p (cross-cutting leverage). Sunshine covers the ~10% of operators who'd accept a client install for materially better latency. Avoid Neko (Docker-overhead), Guacamole (architectural mismatch), noVNC (quality regression).

### VII.2 — gRPC adoption for SDK boundary

**Recommendation: Adopt gRPC + protobuf for SDK delivery (4.6), with protobuf as the schema layer regardless of transport.**

Reasoning: The schema-first move is the dominant value; gRPC-as-transport is the natural pairing. Tonic for Rust is mature. ConnectRPC adoption depends on whether browser-resident SDK consumers are a priority — defensible to start with tonic-only and add Connect adapters if needed.

### VII.3 — Reads as receipts vs. typed-but-unsigned envelopes

**Survey doesn't directly answer this.** Defer to the verb-set design session.

### VII.4 — One-shape vs. local/remote split

**Survey doesn't directly answer this.** Defer.

### VII.5 — Each of seven un-thought dimensions

- **V.1 (trust portability):** **Adopt the hybrid composition** — OpenTimestamps for chain-head anchoring (G.1); libp2p Bitswap + DHT for chain-segment retrieval (G.5); gossipsub for live propagation (C.5). This is the survey's strongest single recommendation because it pulls three already-decided commitments into a coherent answer.
- **V.5 (anchoring threat model):** OpenTimestamps gives "chain state at this hash existed by time T." Defends against retroactive rewrites at hour-to-day granularity. State this as the threat model; avoid claiming defense against shorter-window attacks.
- **V.2 (quorum sovereignty), V.3 (delegation withdrawal), V.4 (trust tier transitions), V.6 (pipeline determinism), V.7 (receipt composability):** Survey doesn't directly answer; deferred to Category I (quorum cryptography) survey when ready and to verb-set design.

### VII.6 — libp2p transport selection

**Recommendation: enable QUIC + TCP + WebSocket + WebRTC by default. Defer WebTransport.**

Reasoning:
- **QUIC** as primary (encrypted, low-latency, multiplexed).
- **TCP** as fallback for environments where QUIC is firewalled.
- **WebSocket** for browser-reachable peers and as a fallback for restrictive networks.
- **WebRTC** because it overlaps with delivery 4.2 and browser-direct P2P scenarios; cost paid once, leverage paid three times.
- **WebTransport** deferred until Safari support lands.

### VII.7 — gossipsub as fourth subscription transport

**Recommendation: Adopt.** Comes free with libp2p commitment; serves the ZP-to-ZP subscription case naturally; doesn't compete with HTTP webhooks (which serve non-ZP subscribers).

---

## Decisions to bring back to the architecture doc

The following can be moved from Part VII (open) to Part II (load-bearing) immediately on Ken's review:

1. **Adopt protobuf as the verb-set schema layer.** Independent of gRPC adoption.
2. **Adopt gRPC + tonic for SDK delivery (4.6).**
3. **Adopt WebRTC + Selkies-GStreamer for delivery 4.2 primary path.**
4. **Adopt libp2p transports: QUIC + TCP + WebSocket + WebRTC** (per VII.6 recommendation).
5. **Adopt gossipsub as the ZP-to-ZP subscription transport** (per VII.7).
6. **Adopt the hybrid composition for V.1 trust portability**: OpenTimestamps + Bitswap + gossipsub.
7. **Adopt OpenTimestamps for V.5 anchoring**, with the threat model explicitly stated as "defends against retroactive chain rewrites at hour-to-day granularity."

The remaining Part VII questions (VII.3, VII.4, V.2/V.3/V.4/V.6/V.7) are not addressable by this survey and stay open.

---

## What this survey does NOT cover

- **Category B (schema / IDL alternatives):** Cap'n Proto, FlatBuffers, CBOR, JSON Schema, Avro. The survey assumes protobuf based on its cross-cutting fit; deeper Category B comparison is a follow-up if protobuf turns out to have fatal flaws we missed.
- **Category E (native UI framework):** Tauri, iced, egui, Slint, etc. Separate survey when delivery 4.1 / 4.2 implementation begins.
- **Category H (identity / authentication):** WebAuthn, PIV, FIDO2 specifics. Separate survey.
- **Category I (quorum / threshold cryptography):** FROST, Shamir, multi-sig patterns. Separate survey when V.2 work begins.
- **Category J (subscription delivery infrastructure at scale):** NATS, Kafka, RabbitMQ. Briefly touched in C.6; revisit when scale demands.
- **Category K (tracing / agent observability):** Forward-looking; no immediate need.

---

*End of survey. Open for review and comment.*
