/**
 * Surface types — represents governed surfaces in ZeroPoint's trust topology.
 *
 * A "surface" is any resource, tool, agent, or endpoint that ZeroPoint
 * governs. Each surface belongs to a trust tier and has capability grants.
 */

export interface Surface {
  id: string;
  name: string;
  type: 'tool' | 'agent' | 'resource' | 'endpoint' | 'service';
  trustTier: 'core' | 'sandboxed' | 'supervised' | 'external';
  status: 'active' | 'inactive' | 'revoked';
  capabilities?: string[];
  /** @deprecated Use componentId instead */
  officer?: string;
  /** Component that governs this surface */
  componentId?: string;
  lastSeen?: number;
  metadata?: Record<string, unknown>;
}

export interface SurfaceCatalog {
  surfaces: Surface[];
  lastUpdated: number;
}

/** Trust tier classification for surfaces */
export type SurfaceTrustTier = 'A' | 'B' | 'C' | 'D' | 'X';
