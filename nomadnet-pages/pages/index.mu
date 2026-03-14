`cF999

`c!ZeroPoint!

`cF777Cryptographic Governance Primitives
`cFaaafor Accountable Systems
`f

-

`lF999Every action produces a verifiable receipt.
Every receipt joins an immutable chain.
The chain is the truth.`f

-

`c>>  About  `f

`lZeroPoint is portable trust infrastructure. It provides
cryptographic primitives that make actions provable,
auditable, and policy-bound -- without requiring central
control. Identity is a keypair you hold. Reputation is
a chain of receipts anyone can verify. Authorization is
a capability grant no one can silently revoke.

The protocol is participant-agnostic: the same receipts,
capability chains, and constitutional constraints work
whether the actor is a human, an AI agent, a service,
or a device.

-

`c>>  Reticulum Integration  `f

`lZeroPoint ships with a Reticulum-compatible mesh transport
as a first-class integration -- chosen for its philosophical
alignment with sovereignty and harm minimization.

Wire-level interoperability:

  `F999*`f HDLC framing with CRC-CCITT verification
  `F999*`f 128-bit destination hashing (truncated SHA-256)
  `F999*`f Ed25519 signing + X25519 ECDH key agreement
  `F999*`f 500-byte MTU / 465-byte payload (LoRa compatible)
  `F999*`f 3-packet link handshake with replay protection

Interoperability tested against MeshChat and NomadNet
over TCP loopback. The mesh transport is one option among
several -- chosen when sovereignty, resilience, or operation
without cloud infrastructure are priorities.

-

`c>>  The Four Tenets  `f

`lFdddI.`f   Do No Harm.
`lFdddII.`f  Sovereignty Is Sacred.
`lFdddIII.`f Action Without Evidence Is No Action.
`lFdddIV.`f  The Human Is The Root.

`lThese are not aspirational statements. They are
constitutional rules embedded in the protocol, enforced
by the policy engine, and non-removable by any operator,
policy module, or consensus vote.

-

`c>>  Technical Status  `f

`l  `F999*`f 700+ tests across 13 Rust crates
  `F999*`f Full CI/CD (GitHub Actions)
  `F999*`f MIT / Apache-2.0 dual license
  `F999*`f Whitepaper v1.1 published
  `F999*`f Course: 16 hands-on labs

-

`c>>  Pages  `f

`c`[Architecture`:/page/architecture.mu]
`c`[The Presence Plane`:/page/presence.mu]
`c`[Links + Contact`:/page/links.mu]

-

`cF777Built on Reticulum. Wire-compatible.
`cSovereign by design.`f

`cF555ZeroPoint v0.1.0 | ThinkStream Labs`f

