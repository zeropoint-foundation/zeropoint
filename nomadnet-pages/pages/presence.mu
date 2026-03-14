`cF999

`c!The Presence Plane!

`cF777Peer Discovery Without Surveillance
`f

-

`c>>  The Problem  `f

`lMost systems solve peer discovery with a centralized
registry: a server that indexes who is online, what they
offer, and where to reach them. This creates exactly the
dependency ZeroPoint exists to eliminate -- a single point
of surveillance, censorship, and failure.

-

`c>>  Dual-Backend Discovery  `f

`lThe Presence Plane uses two backends simultaneously:

`Fddd  Web Relay`f
  Privacy-preserving pub/sub over WebSocket. Agents publish
  signed announce blobs; the relay broadcasts to all
  subscribers; agents filter locally. The relay never
  parses payloads, never indexes capabilities, never logs
  queries, and never persists state. Restart = clean slate.

`Fddd  Reticulum Mesh`f
  Broadcast over mesh interfaces -- LoRa, WiFi, serial,
  TCP. Fully decentralized. No server. No internet
  dependency. Announces propagate over whatever physical
  medium is available.

`lBoth backends share the same wire format:
  [combined_key(64)] + [capabilities_json] + [signature(64)]

A peer discovered via web and a peer discovered via mesh
end up in the same peer table with the same destination
hash. The DiscoveryManager fans out announces, validates
signatures, deduplicates, and prunes expired entries.

-

`c>>  Structural Amnesia  `f

`lThe web relay is designed to be _structurally_ incapable
of surveillance -- not merely configured to avoid it:

  `F999*`f Does not parse announce payloads
  `F999*`f Does not maintain query logs
  `F999*`f Does not persist any state (memory only)
  `F999*`f Does not track who received what

`lSubpoena-proof: nothing to hand over.
Compromise-proof: attacker finds zero peer data.
Structural amnesia > policy-based privacy.

-

`c>>  Reciprocity Enforcement  `f

`lPassive scanning is the primary adversarial concern.
The Presence Plane enforces a reciprocity rule:

  !You must announce before you receive.!

`lA connection that only subscribes without publishing its
own announce is a consumer-only node -- a passive scanner.
The relay tracks this. Scanners become observable before
they can observe.

-

`c`[Back to Index`:/page/index.mu]

`cF555ZeroPoint v0.1.0 | ThinkStream Labs`f

