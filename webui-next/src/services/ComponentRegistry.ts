/**
 * ComponentRegistry — Client-side projection of zp-mesh's peer table
 *
 * Maintains the dashboard's view of the live mesh topology. Fed by
 * WebSocket messages from zp-server, which projects the Rust-side
 * MeshNode.known_peers() and link table into JSON.
 *
 * Wire protocol messages (from zp-server over existing /wss endpoint):
 *
 *   topology.snapshot   — Full topology (peers + links + candidates)
 *                         Sent on WebSocket connect and reconnect.
 *
 *   topology.announce   — New peer seen (AgentAnnounce envelope received)
 *                         Payload: MeshPeer
 *
 *   topology.heartbeat  — Peer health update (capabilities refresh)
 *                         Payload: { address: string, lastSeen: string,
 *                                    capabilities?: MeshCapabilities }
 *
 *   topology.link       — Link state change
 *                         Payload: MeshLink
 *
 *   topology.gone       — Peer unreachable or link closed
 *                         Payload: { address: string }
 *
 *   topology.candidate  — Brownfield discovery candidate
 *                         Payload: MeshDiscoveryCandidate
 *
 * Consumers subscribe via subscribe() and receive the full MeshTopology
 * on every change. MapStation is the primary consumer.
 */

import type {
  MeshPeer,
  MeshLink,
  MeshTopology,
  MeshDiscoveryCandidate,
  MeshCapabilities,
} from '../types/component';

// =============================================================================
// REGISTRY STATE
// =============================================================================

type TopologyListener = (topology: MeshTopology) => void;

let _peers: Map<string, MeshPeer> = new Map();           // address → peer
let _links: Map<string, MeshLink> = new Map();           // id → link
let _candidates: Map<string, MeshDiscoveryCandidate> = new Map();  // candidateId → candidate
let _listeners: Set<TopologyListener> = new Set();
let _lastUpdated: string = new Date().toISOString();

// =============================================================================
// READ — Snapshot access
// =============================================================================

/** Get the current topology graph */
export function getTopology(): MeshTopology {
  return {
    peers: Array.from(_peers.values()),
    links: Array.from(_links.values()),
    candidates: Array.from(_candidates.values()),
    timestamp: _lastUpdated,
  };
}

/** Get a single peer by address */
export function getPeer(address: string): MeshPeer | undefined {
  return _peers.get(address);
}

/** Get all peers with active links */
export function getLinkedPeers(): MeshPeer[] {
  return Array.from(_peers.values()).filter(p => p.hasLink);
}

/** Get links for a specific peer */
export function getPeerLinks(address: string): MeshLink[] {
  return Array.from(_links.values()).filter(
    l => l.localAddress === address || l.remoteAddress === address
  );
}

// =============================================================================
// WRITE — Called by BridgeContext WebSocket handler
// =============================================================================

/** Replace the entire topology (on connect / reconnect) */
export function loadSnapshot(topology: MeshTopology): void {
  _peers = new Map(topology.peers.map(p => [p.address, p]));
  _links = new Map(topology.links.map(l => [l.id, l]));
  _candidates = new Map(topology.candidates.map(c => [c.candidateId, c]));
  _lastUpdated = topology.timestamp;
  _notify();
}

/** Add or update a peer (from topology.announce) */
export function upsertPeer(peer: MeshPeer): void {
  _peers.set(peer.address, peer);
  _lastUpdated = new Date().toISOString();
  _notify();
}

/** Update peer health from heartbeat */
export function updatePeerHealth(
  address: string,
  lastSeen: string,
  capabilities?: MeshCapabilities,
): void {
  const peer = _peers.get(address);
  if (!peer) return;
  _peers.set(address, {
    ...peer,
    lastSeen,
    ...(capabilities ? { capabilities } : {}),
  });
  _lastUpdated = lastSeen;
  _notify();
}

/** Remove a peer (from topology.gone) */
export function removePeer(address: string): void {
  _peers.delete(address);
  // Remove links involving this peer
  for (const [id, link] of _links) {
    if (link.localAddress === address || link.remoteAddress === address) {
      _links.delete(id);
    }
  }
  _lastUpdated = new Date().toISOString();
  _notify();
}

/** Add or update a link (from topology.link) */
export function upsertLink(link: MeshLink): void {
  _links.set(link.id, link);
  _lastUpdated = new Date().toISOString();
  _notify();
}

/** Remove a link */
export function removeLink(linkId: string): void {
  _links.delete(linkId);
  _lastUpdated = new Date().toISOString();
  _notify();
}

/** Add a discovery candidate (from topology.candidate) */
export function addCandidate(candidate: MeshDiscoveryCandidate): void {
  _candidates.set(candidate.candidateId, candidate);
  _lastUpdated = new Date().toISOString();
  _notify();
}

/** Remove a discovery candidate (enrolled or dismissed) */
export function removeCandidate(candidateId: string): void {
  _candidates.delete(candidateId);
  _lastUpdated = new Date().toISOString();
  _notify();
}

// =============================================================================
// SUBSCRIBE — Reactive topology updates
// =============================================================================

/** Subscribe to topology changes. Returns unsubscribe function. */
export function subscribe(listener: TopologyListener): () => void {
  _listeners.add(listener);
  return () => { _listeners.delete(listener); };
}

function _notify(): void {
  const topology = getTopology();
  for (const listener of _listeners) {
    try { listener(topology); } catch { /* swallow listener errors */ }
  }
}

// =============================================================================
// RESET — For testing and reconnection
// =============================================================================

export function reset(): void {
  _peers.clear();
  _links.clear();
  _candidates.clear();
  _lastUpdated = new Date().toISOString();
  _notify();
}
