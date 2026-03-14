# LXMF Message to Mark Qvist

**Purpose**: First contact introduction of ZeroPoint, sent via LXMF through Reticulum.
**Tone**: Respectful, technical, honest about what it is and isn't. Lead with the work, not the pitch.
**Length**: Short enough to read in a terminal. No attachments on first contact.

---

## Message

Mark,

My name is Ken Romero. I'm a developer working on a project called ZeroPoint — cryptographic governance primitives for accountable systems, with a focus on autonomous AI agents. I'm reaching out via Reticulum because this is where it makes sense to, and because ZeroPoint includes a Reticulum-compatible mesh transport that I'd like your perspective on.

The short version: ZeroPoint provides signed receipts, immutable audit chains, capability-scoped delegation, and a policy engine with constitutional constraints that can't be overridden. Every action produces a verifiable receipt. The protocol is participant-agnostic — same primitives whether the actor is a human, an agent, or a device.

The Reticulum integration is wire-compatible: HDLC framing with CRC-CCITT, 128-bit destination hashing via truncated SHA-256, Ed25519 + X25519 key agreement, 500-byte MTU, and a 3-packet link handshake. I've tested it against MeshChat over TCP loopback with receipt chain exchanges and signature verification passing cleanly.

The project also includes what I call the Presence Plane — a dual-backend discovery layer. One backend is a privacy-preserving web relay (structurally amnesic — it cannot parse, index, or persist anything it forwards). The other is Reticulum mesh broadcast. Both share the same announce wire format and feed the same peer table. The design enforces reciprocity: you must announce before you receive, which makes passive scanning observable.

I built this because I believe trust should be a protocol property, not a platform feature. The philosophical alignment with Reticulum's values — sovereignty, no central authority, harm minimization — is genuine and runs through the architecture. ZeroPoint's constitutional rules (Do No Harm, Sovereignty Is Sacred) are non-removable by any operator or policy module. They're a technical property, not a promise.

The code is open source (MIT/Apache-2.0), written in Rust, with 700+ tests across 13 crates and full CI. I'm not looking for endorsement — I'd welcome your honest feedback on the transport layer implementation and whether I've gotten the interoperability right. The repo is at github.com/zeropoint-foundation/zeropoint and I'm hosting a NomadNet node with more details.

Thank you for building Reticulum. It changed how I think about what networks should be.

Ken Romero
ThinkStream Labs
