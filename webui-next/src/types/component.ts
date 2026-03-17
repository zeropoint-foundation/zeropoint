/**
 * ZPComponent — TypeScript projection of zp-mesh Rust types
 *
 * These types mirror the Rust structs in crates/zp-mesh/src/ to provide
 * a coherent end-to-end representation of the trust mesh in the dashboard.
 *
 * Rust source of truth:
 *   identity.rs  → MeshIdentity, PeerIdentity
 *   transport.rs → AgentCapabilities, PeerInfo, AgentTransport
 *   envelope.rs  → MeshEnvelope, EnvelopeType, CompactReceipt
 *   link.rs      → Link, LinkState, SessionKeys
 *   discovery.rs → DiscoveryManager, DiscoveredPeer
 *   packet.rs    → Packet, DestinationHash
 *
 * The dashboard is a read-only consumer. The Rust server (zp-server) owns
 * the canonical peer table and projects it to the UI via WebSocket messages:
 *
 *   topology.snapshot  — Full peer table (on connect / reconnect)
 *   topology.announce  — New peer announced (AgentAnnounce envelope)
 *   topology.heartbeat — Peer health update
 *   topology.gone      — Peer unreachable or link closed
 *   topology.candidate — Discovered but unenrolled node (brownfield)
 */

import type { SurfaceTrustTier } from './surface';

// =============================================================================
// PEER IDENTITY — Mirrors zp-mesh::identity::PeerIdentity
// =============================================================================

/**
 * A mesh peer's public identity — learned from announce packets.
 *
 * Mirrors PeerIdentity in crates/zp-mesh/src/identity.rs.
 * The destination hash (128-bit, hex) is the canonical address.
 */
export interface MeshPeerIdentity {
  /** Ed25519 public key — 32 bytes, hex-encoded */
  signingKey: string;
  /** X25519 public key — 32 bytes, hex-encoded */
  encryptionKey: string;
  /** 128-bit destination hash — SHA-256(signing ‖ encryption), truncated. Hex. */
  destinationHash: string;
  /** When this identity was first seen (ISO timestamp) */
  firstSeen: string;
  /** When this identity was last announced (ISO timestamp) */
  lastAnnounced: string;
  /** Number of hops in the last announce */
  hops: number;
}

// =============================================================================
// AGENT CAPABILITIES — Mirrors zp-mesh::transport::AgentCapabilities
// =============================================================================

/**
 * Capabilities announced to the mesh via AgentAnnounce envelopes.
 *
 * Mirrors AgentCapabilities in crates/zp-mesh/src/transport.rs.
 */
export interface MeshCapabilities {
  /** Human-readable name */
  name: string;
  /** Software version */
  version: string;
  /** Supported receipt types (e.g., ['execution', 'intent', 'approval']) */
  receiptTypes: string[];
  /** Available skills/tools */
  skills: string[];
  /** Actor type: 'human' | 'codex' | 'agent' | 'sentinel' | 'service' */
  actorType: string;
  /** Trust tier this peer operates at */
  trustTier: string;
}

// =============================================================================
// PEER INFO — Mirrors zp-mesh::transport::PeerInfo
// =============================================================================

/**
 * Information about a known mesh peer — the primary type for topology display.
 *
 * Mirrors PeerInfo in crates/zp-mesh/src/transport.rs.
 * This is what MeshNode.known_peers() returns.
 */
export interface MeshPeer {
  /** Hex destination hash — the peer's mesh address */
  address: string;
  /** Number of hops away */
  hops: number;
  /** Last time we heard from this peer (ISO timestamp) */
  lastSeen: string;
  /** Announced capabilities (if known from AgentAnnounce) */
  capabilities?: MeshCapabilities;
  /** Whether we have an active encrypted link to this peer */
  hasLink: boolean;
}

// =============================================================================
// LINK STATE — Mirrors zp-mesh::link::LinkState
// =============================================================================

/** Link lifecycle state — mirrors LinkState enum in link.rs */
export type MeshLinkState = 'pending' | 'active' | 'closing' | 'closed';

/**
 * An active or pending link between two peers.
 * Links provide forward-secret encrypted channels.
 */
export interface MeshLink {
  /** Link identifier */
  id: string;
  /** Local peer address */
  localAddress: string;
  /** Remote peer address */
  remoteAddress: string;
  /** Current link state */
  state: MeshLinkState;
  /** Packets sent over this link */
  packetsSent: number;
  /** Packets received over this link */
  packetsReceived: number;
  /** Round-trip time in ms (if measured) */
  rttMs?: number;
  /** When the link was established (ISO timestamp) */
  establishedAt?: string;
}

// =============================================================================
// COMPONENT TYPE — Dashboard-layer enrichment over MeshPeer
// =============================================================================

/**
 * Component type taxonomy — inferred from capabilities or declared.
 *
 * This extends the mesh-level peer concept with UI-layer semantics.
 * The Rust layer doesn't care about component types — it only knows
 * peers and capabilities. The dashboard infers types from capabilities.
 */
export type ZPComponentType =
  | 'core'               // ZeroPoint Core server
  | 'sentinel'           // Network-edge guardian (router, firewall)
  | 'dns-shield'         // DNS filtering/monitoring
  | 'agent-framework'    // AI agent runtime (LangGraph, CrewAI, etc.)
  | 'vault'              // Credential/secret management
  | 'ledger'             // Audit/attestation ledger
  | 'relay'              // Message relay / event bus
  | 'monitor'            // Observability collector
  | 'gateway'            // API gateway / ingress
  | 'sandbox'            // Sandboxed execution environment
  | 'storage'            // Artifact / evidence storage
  | 'custom';            // Unknown / user-defined

/**
 * Infer component type from mesh capabilities.
 *
 * The Rust mesh layer is type-agnostic — it deals in capabilities.
 * The UI layer maps capabilities to component types for display.
 */
export function inferComponentType(capabilities?: MeshCapabilities): ZPComponentType {
  if (!capabilities) return 'custom';
  const { actorType, skills } = capabilities;

  if (actorType === 'sentinel') return 'sentinel';
  if (actorType === 'service') {
    if (skills.some(s => s.includes('dns'))) return 'dns-shield';
    if (skills.some(s => s.includes('vault') || s.includes('credential'))) return 'vault';
    if (skills.some(s => s.includes('audit') || s.includes('ledger'))) return 'ledger';
    if (skills.some(s => s.includes('monitor') || s.includes('trace'))) return 'monitor';
    if (skills.some(s => s.includes('gateway') || s.includes('ingress'))) return 'gateway';
    if (skills.some(s => s.includes('storage') || s.includes('artifact'))) return 'storage';
    return 'relay';
  }
  if (actorType === 'agent' || actorType === 'codex') return 'agent-framework';
  if (actorType === 'human') return 'core';

  return 'custom';
}

// =============================================================================
// TOPOLOGY GRAPH — What the dashboard renders
// =============================================================================

/**
 * The complete topology snapshot — projected from zp-mesh's peer table
 * and link table via the WebSocket. This is what MapStation renders.
 */
export interface MeshTopology {
  /** Known mesh peers (from MeshNode.known_peers()) */
  peers: MeshPeer[];
  /** Active/pending links between peers */
  links: MeshLink[];
  /** Discovered but unenrolled nodes (brownfield candidates) */
  candidates: MeshDiscoveryCandidate[];
  /** Snapshot timestamp (ISO) */
  timestamp: string;
}

// =============================================================================
// DISCOVERY — Mirrors zp-mesh::discovery
// =============================================================================

/** How a candidate was discovered — mirrors DiscoverySource in discovery.rs */
export type MeshDiscoverySource = 'web' | 'reticulum' | 'manual';

/**
 * A discovered but unenrolled node — candidate for mesh enrollment.
 *
 * Mirrors DiscoveredPeer in crates/zp-mesh/src/discovery.rs.
 * Found via Web discovery relay or Reticulum broadcast.
 */
export interface MeshDiscoveryCandidate {
  /** Temporary ID */
  candidateId: string;
  /** Discovery source */
  source: MeshDiscoverySource;
  /** Network address (if known) */
  address?: string;
  /** Inferred capabilities from announce data */
  inferredCapabilities?: Partial<MeshCapabilities>;
  /** Whether the candidate responded to a ZP handshake */
  zpAware: boolean;
  /** When first discovered (ISO timestamp) */
  firstSeen: string;
  /** When last seen (ISO timestamp) */
  lastSeen: string;
}

// =============================================================================
// ENVELOPE TYPE — Mirrors zp-mesh::envelope::EnvelopeType
// =============================================================================

/**
 * Envelope types carried over the mesh wire.
 * The dashboard only needs to know about a few of these for display.
 *
 * Mirrors EnvelopeType enum in crates/zp-mesh/src/envelope.rs.
 */
export type MeshEnvelopeType =
  | 'receipt'              // 0x01 — CompactReceipt
  | 'delegation'           // 0x02 — CapabilityGrant
  | 'guard-request'        // 0x03
  | 'guard-response'       // 0x04
  | 'agent-announce'       // 0x05 — AgentCapabilities
  | 'receipt-chain'        // 0x06
  | 'policy-advertisement' // 0x10
  | 'audit-challenge'      // 0x20
  | 'audit-response'       // 0x21
  | 'audit-attestation'    // 0x22
  | 'reputation-summary';  // 0x30

// =============================================================================
// COMPONENT TYPE METADATA — Display hints for the topology view
// =============================================================================

/** Visual metadata for rendering component types in the topology */
export const COMPONENT_TYPE_META: Record<ZPComponentType, {
  label: string;
  icon: string;
  color: string;
  description: string;
}> = {
  core:             { label: 'Core',             icon: '◈', color: '#3b82f6', description: 'ZeroPoint Core server' },
  sentinel:         { label: 'Sentinel',         icon: '⛊', color: '#7eb8da', description: 'Network-edge guardian' },
  'dns-shield':     { label: 'DNS Shield',       icon: '⊘', color: '#10b981', description: 'DNS filtering & monitoring' },
  'agent-framework':{ label: 'Agent Framework',  icon: '◇', color: '#8b5cf6', description: 'AI agent runtime' },
  vault:            { label: 'Vault',            icon: '🔐', color: '#7c3aed', description: 'Credential management' },
  ledger:           { label: 'Ledger',           icon: '📋', color: '#a855f7', description: 'Audit & attestation ledger' },
  relay:            { label: 'Relay',            icon: '⇌', color: '#f59e0b', description: 'Message relay / event bus' },
  monitor:          { label: 'Monitor',          icon: '◉', color: '#f97316', description: 'Observability collector' },
  gateway:          { label: 'Gateway',          icon: '⊞', color: '#0891b2', description: 'API gateway / ingress' },
  sandbox:          { label: 'Sandbox',          icon: '▣', color: '#64748b', description: 'Sandboxed execution environment' },
  storage:          { label: 'Storage',          icon: '▤', color: '#78716c', description: 'Artifact & evidence storage' },
  custom:           { label: 'Custom',           icon: '◎', color: '#6b7280', description: 'User-defined component' },
};

/** Trust tier display metadata */
export const TRUST_TIER_META: Record<SurfaceTrustTier, {
  label: string;
  color: string;
  description: string;
}> = {
  A: { label: 'Core Trust',   color: '#3b82f6', description: 'Fully attested, cryptographically verified' },
  B: { label: 'Supervised',   color: '#8b5cf6', description: 'Trust boundaries applied, monitored' },
  C: { label: 'Sandboxed',    color: '#f59e0b', description: 'Isolated execution, limited capabilities' },
  D: { label: 'Untrusted',    color: '#ef4444', description: 'Newly registered, unverified' },
  X: { label: 'External',     color: '#6b7280', description: 'Outside the trust boundary' },
};
