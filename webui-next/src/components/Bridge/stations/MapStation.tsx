/**
 * MapStation — Mesh topology visualization
 *
 * Renders the live zp-mesh peer graph. Each peer is shown with its
 * inferred component type, capabilities, hop count, and link status.
 * Discovery candidates appear as dashed ghost nodes for enrollment.
 *
 * Data source: ComponentRegistry (projecting MeshNode.known_peers()
 * from the Rust server via WebSocket topology.* messages).
 *
 * Lazy-loaded by OperationsSection.
 */

import { useState, useEffect, useMemo } from 'react';
import type { SystemStatus } from '../types';
import type { MeshPeer, MeshTopology, MeshDiscoveryCandidate } from '@/types/component';
import { COMPONENT_TYPE_META, TRUST_TIER_META, inferComponentType } from '@/types/component';
import type { SurfaceTrustTier } from '@/types/surface';
import { getTopology, subscribe } from '@/services/ComponentRegistry';

interface MapStationProps {
  systemStatus: SystemStatus;
}

/** Peer state color based on recency and link status */
function peerStateColor(peer: MeshPeer): string {
  if (!peer.lastSeen) return 'bg-gray-500';
  const age = Date.now() - new Date(peer.lastSeen).getTime();
  if (age > 120_000) return 'bg-red-400';      // >2min — likely unreachable
  if (age > 60_000) return 'bg-amber-400';      // >1min — stale
  if (peer.hasLink) return 'bg-emerald-400';     // Active link
  return 'bg-blue-400';                          // Seen recently, no link
}

/** Peer state label */
function peerStateLabel(peer: MeshPeer): string {
  const age = Date.now() - new Date(peer.lastSeen).getTime();
  if (age > 120_000) return 'Unreachable';
  if (age > 60_000) return 'Stale';
  if (peer.hasLink) return 'Linked';
  return 'Seen';
}

export default function MapStation({ systemStatus }: MapStationProps) {
  const [topology, setTopology] = useState<MeshTopology>(getTopology);

  useEffect(() => subscribe(setTopology), []);

  const { peers, links, candidates } = topology;
  const isEmpty = peers.length === 0 && candidates.length === 0;

  return (
    <div className="h-full flex flex-col bg-gray-900/40 p-6">
      {/* Header */}
      <div className="text-gray-500 text-sm uppercase tracking-wider text-center mb-6">
        Mesh Topology
      </div>

      {/* Topology graph */}
      <div className="flex-1 flex items-center justify-center">
        <div className="flex items-start gap-8 justify-center">
          {/* Core node — always present (this is us) */}
          <div className="flex flex-col items-center gap-2">
            <div className="w-16 h-16 rounded-full bg-blue-900/40 border-2 border-blue-500/40 flex items-center justify-center relative">
              <span className="text-blue-400 text-lg">◈</span>
              {systemStatus?.online && (
                <div className="absolute -top-0.5 -right-0.5 w-3 h-3 rounded-full bg-emerald-400 border-2 border-gray-900" />
              )}
            </div>
            <span className="text-xs text-gray-400">Core</span>
            <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-blue-900/30 text-blue-400">
              Local
            </span>
          </div>

          {/* Connection lines to peers */}
          {!isEmpty && (
            <div className="flex flex-col gap-3 pt-4 justify-center">
              {peers.map(p => (
                <div
                  key={p.address}
                  className={`w-16 h-px ${p.hasLink ? 'bg-emerald-700' : 'bg-gray-700'}`}
                />
              ))}
              {candidates.map(c => (
                <div key={c.candidateId} className="w-16 h-px bg-gray-700/30 border-t border-dashed border-gray-700" />
              ))}
            </div>
          )}

          {/* Peer nodes */}
          {!isEmpty && (
            <div className="flex flex-col gap-2">
              {peers.map(peer => {
                const componentType = inferComponentType(peer.capabilities);
                const meta = COMPONENT_TYPE_META[componentType];
                const tierKey = (peer.capabilities?.trustTier ?? 'D') as SurfaceTrustTier;
                const tierMeta = TRUST_TIER_META[tierKey] ?? TRUST_TIER_META.D;

                return (
                  <div key={peer.address} className="flex items-center gap-2 group">
                    {/* Health dot */}
                    <div className={`w-2.5 h-2.5 rounded-full ${peerStateColor(peer)} shrink-0`} />
                    {/* Type icon */}
                    <div
                      className="w-8 h-8 rounded-md border border-white/10 flex items-center justify-center shrink-0"
                      style={{ backgroundColor: `${meta.color}20`, borderColor: `${meta.color}40` }}
                    >
                      <span className="text-sm" style={{ color: meta.color }}>{meta.icon}</span>
                    </div>
                    {/* Labels */}
                    <div className="flex flex-col min-w-0">
                      <span className="text-xs text-gray-300 truncate">
                        {peer.capabilities?.name || `Peer ${peer.address.slice(0, 8)}`}
                      </span>
                      <div className="flex items-center gap-1.5">
                        <span className="text-[9px] text-gray-500">{meta.label}</span>
                        <span className="text-[9px] text-gray-600">·</span>
                        <span className="text-[9px]" style={{ color: tierMeta.color }}>
                          {tierMeta.label}
                        </span>
                        <span className="text-[9px] text-gray-600">·</span>
                        <span className="text-[9px] text-gray-500">{peerStateLabel(peer)}</span>
                        {peer.hops > 0 && (
                          <>
                            <span className="text-[9px] text-gray-600">·</span>
                            <span className="text-[9px] text-gray-500">
                              {peer.hops} hop{peer.hops !== 1 ? 's' : ''}
                            </span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}

              {/* Discovery candidates — ghost nodes */}
              {candidates.map(candidate => {
                const inferredType = inferComponentType(
                  candidate.inferredCapabilities as MeshPeer['capabilities'],
                );
                const meta = COMPONENT_TYPE_META[inferredType];
                return (
                  <div key={candidate.candidateId} className="flex items-center gap-2 opacity-50">
                    <div className="w-2.5 h-2.5 rounded-full bg-gray-500 animate-pulse shrink-0" />
                    <div className="w-8 h-8 rounded-md border border-dashed border-gray-600 flex items-center justify-center shrink-0">
                      <span className="text-sm text-gray-500">{meta.icon}</span>
                    </div>
                    <div className="flex flex-col min-w-0">
                      <span className="text-xs text-gray-500 truncate italic">
                        {candidate.address || candidate.candidateId.slice(0, 12)}
                      </span>
                      <div className="flex items-center gap-1.5">
                        <span className="text-[9px] text-gray-600">
                          {candidate.zpAware ? 'ZP-aware' : 'Unmanaged'}
                        </span>
                        <span className="text-[9px] text-gray-600">·</span>
                        <span className="text-[9px] text-gray-600">via {candidate.source}</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Empty state */}
          {isEmpty && (
            <div className="flex items-center gap-3 pt-4">
              <div className="w-16 h-px bg-gray-700/50" />
              <div className="flex flex-col gap-1">
                <span className="text-xs text-gray-600 italic">No peers on the mesh</span>
                <span className="text-[9px] text-gray-700">
                  Peers announce via AgentAnnounce envelopes on the mesh transport
                </span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Footer stats */}
      <div className="text-[10px] text-gray-600 text-center mt-4">
        {peers.length} peer{peers.length !== 1 ? 's' : ''}
        {links.length > 0 && ` · ${links.length} link${links.length !== 1 ? 's' : ''}`}
        {candidates.length > 0 && ` · ${candidates.length} candidate${candidates.length !== 1 ? 's' : ''}`}
      </div>
    </div>
  );
}
