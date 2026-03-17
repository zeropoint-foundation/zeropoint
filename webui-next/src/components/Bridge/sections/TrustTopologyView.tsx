/**
 * TrustTopologyView — Concentric Trust-Ring Diagram
 *
 * SVG visualization showing ZeroPoint's layered security architecture:
 * four nested elliptical rings (Trust Core → Sandboxed → Supervised → Host/External)
 * with governed surfaces mapped to their trust tiers.
 *
 * Pure trust architecture view — no agent placements. Agents are shown
 * in the sidebar and dashboard; this surface focuses on WHAT is governed
 * and WHERE it sits in the trust hierarchy.
 */

import { useState, useCallback, useMemo, useRef } from 'react';
import { useSurfaceSafe } from '@/hooks/useSurface';
import type { Surface } from '@/types/surface';

// ─── Trust Ring Definitions ───

const TRUST_RINGS = [
  { tier: 'Host / External', color: '#ef4444', bg: 'rgba(127,29,29,0.15)', desc: 'Human co-sign · Short TTL', grade: 'D/X' },
  { tier: 'Supervised', color: '#f59e0b', bg: 'rgba(120,53,15,0.15)', desc: 'ACP bridge · Receipt-gated', grade: 'B' },
  { tier: 'Sandboxed', color: '#3b82f6', bg: 'rgba(30,58,138,0.15)', desc: 'MCP tools · Scoped access', grade: 'C' },
  { tier: 'Trust Core', color: '#22c55e', bg: 'rgba(20,83,45,0.2)', desc: 'Receipts · Attestation · Policy', grade: 'A' },
] as const;

// ─── SVG Canvas Constants ───

const TOPO_W = 720;
const TOPO_H = 480;
const TOPO_CX = TOPO_W / 2;
const TOPO_CY = TOPO_H / 2;
const MIN_ZOOM = 0.4;
const MAX_ZOOM = 4;
const ZOOM_STEP = 0.15;

const TOPO_RINGS = [
  { rx: 340, ry: 220 }, // Host/External
  { rx: 270, ry: 175 }, // Supervised
  { rx: 200, ry: 130 }, // Sandboxed
  { rx: 120, ry: 78 },  // Trust Core
];

// ─── Component ───

export default function TrustTopologyView() {
  const surfaceData = useSurfaceSafe();
  const surfaces: Surface[] = surfaceData?.surfaces ?? [];

  // Zoom & pan state
  const [zoom, setZoom] = useState(1);
  const [center, setCenter] = useState({ x: TOPO_CX, y: TOPO_CY });
  const [isPanning, setIsPanning] = useState(false);
  const panStart = useRef({ x: 0, y: 0, cx: TOPO_CX, cy: TOPO_CY });
  const containerRef = useRef<HTMLDivElement>(null);

  const clampZoom = useCallback((z: number) => Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, z)), []);

  const zoomAt = useCallback((newZoom: number, svgX: number, svgY: number) => {
    const clamped = clampZoom(newZoom);
    setCenter((prev) => ({
      x: svgX + (prev.x - svgX) * (zoom / clamped),
      y: svgY + (prev.y - svgY) * (zoom / clamped),
    }));
    setZoom(clamped);
  }, [zoom, clampZoom]);

  const clientToSvg = useCallback((clientX: number, clientY: number) => {
    const el = containerRef.current;
    if (!el) return { x: TOPO_CX, y: TOPO_CY };
    const rect = el.getBoundingClientRect();
    const vbW = TOPO_W / zoom;
    const vbH = TOPO_H / zoom;
    const vbX = center.x - vbW / 2;
    const vbY = center.y - vbH / 2;
    return {
      x: vbX + ((clientX - rect.left) / rect.width) * vbW,
      y: vbY + ((clientY - rect.top) / rect.height) * vbH,
    };
  }, [zoom, center]);

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? -ZOOM_STEP : ZOOM_STEP;
    const svgPt = clientToSvg(e.clientX, e.clientY);
    zoomAt(zoom + delta, svgPt.x, svgPt.y);
  }, [zoom, clientToSvg, zoomAt]);

  const handleZoomIn = useCallback(() => {
    zoomAt(zoom + ZOOM_STEP, center.x, center.y);
  }, [zoom, center, zoomAt]);

  const handleZoomOut = useCallback(() => {
    zoomAt(zoom - ZOOM_STEP, center.x, center.y);
  }, [zoom, center, zoomAt]);

  const handleReset = useCallback(() => {
    setZoom(1);
    setCenter({ x: TOPO_CX, y: TOPO_CY });
  }, []);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button !== 0) return;
    setIsPanning(true);
    panStart.current = { x: e.clientX, y: e.clientY, cx: center.x, cy: center.y };
  }, [center]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!isPanning) return;
    const el = containerRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const svgPerPxX = (TOPO_W / zoom) / rect.width;
    const svgPerPxY = (TOPO_H / zoom) / rect.height;
    const dx = (e.clientX - panStart.current.x) * svgPerPxX;
    const dy = (e.clientY - panStart.current.y) * svgPerPxY;
    setCenter({ x: panStart.current.cx - dx, y: panStart.current.cy - dy });
  }, [isPanning, zoom]);

  const handleMouseUp = useCallback(() => {
    setIsPanning(false);
  }, []);

  // Compute viewBox
  const vbW = TOPO_W / zoom;
  const vbH = TOPO_H / zoom;
  const vbX = center.x - vbW / 2;
  const vbY = center.y - vbH / 2;
  const viewBox = `${vbX} ${vbY} ${vbW} ${vbH}`;

  // Map surfaces to ring positions
  const surfaceNodes = useMemo(() => {
    const tierToGrade = (t: string): string => {
      switch (t) {
        case 'core': return 'A';
        case 'sandboxed': return 'C';
        case 'supervised': return 'B';
        case 'external': return 'X';
        default: return 'X';
      }
    };
    return surfaces.map((s) => {
      const tier = tierToGrade(s.trustTier);
      const ring = tier === 'A' ? 3 : tier === 'B' ? 2 : tier === 'C' ? 1 : 0;
      return { id: s.id, name: s.name, tier, ring, isActive: s.status === 'active' };
    });
  }, [surfaces]);

  // Distribute surfaces evenly around their rings
  const surfacePositions = useMemo(() => {
    const byRing: Record<number, typeof surfaceNodes> = {};
    surfaceNodes.forEach((s) => {
      if (!byRing[s.ring]) byRing[s.ring] = [];
      byRing[s.ring].push(s);
    });
    const positions: { id: string; name: string; x: number; y: number; isActive: boolean; tier: string }[] = [];
    Object.entries(byRing).forEach(([ringStr, nodes]) => {
      const ringIdx = Number(ringStr);
      const r = TOPO_RINGS[ringIdx];
      if (!r) return;
      const count = nodes.length;
      nodes.forEach((node, i) => {
        // Distribute evenly around the full ellipse
        const angle = (2 * Math.PI * i) / count - Math.PI / 2; // start from top
        positions.push({
          id: node.id,
          name: node.name,
          x: TOPO_CX + r.rx * 0.8 * Math.cos(angle),
          y: TOPO_CY + r.ry * 0.8 * Math.sin(angle),
          isActive: node.isActive,
          tier: node.tier,
        });
      });
    });
    return positions;
  }, [surfaceNodes]);

  // Summary counts per ring
  const ringCounts = useMemo(() => {
    const counts = [0, 0, 0, 0]; // [host, supervised, sandboxed, core]
    surfaceNodes.forEach(s => counts[s.ring]++);
    return counts;
  }, [surfaceNodes]);

  return (
    <div className="h-full flex flex-col overflow-hidden relative">
      {/* SVG canvas with zoom/pan */}
      <div
        ref={containerRef}
        className="flex-1 min-h-0"
        onWheel={handleWheel}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        style={{ cursor: isPanning ? 'grabbing' : 'grab' }}
      >
        <svg
          viewBox={viewBox}
          className="w-full h-full"
          style={{ fontFamily: 'ui-monospace, monospace' }}
          preserveAspectRatio="xMidYMid meet"
        >
          {/* Ring layers (outer to inner) */}
          {TOPO_RINGS.map((r, i) => {
            const ring = TRUST_RINGS[i];
            return (
              <g key={i}>
                <ellipse
                  cx={TOPO_CX} cy={TOPO_CY} rx={r.rx} ry={r.ry}
                  fill={ring.bg}
                  stroke={ring.color}
                  strokeWidth={1.5}
                  strokeOpacity={0.4}
                  strokeDasharray={i === 0 ? '6 4' : 'none'}
                />
                <text
                  x={TOPO_CX + r.rx - 4}
                  y={TOPO_CY - r.ry + 16}
                  fill={ring.color}
                  fontSize={9}
                  fontWeight="bold"
                  textAnchor="end"
                  opacity={0.7}
                >
                  {ring.tier}
                </text>
                <text
                  x={TOPO_CX + r.rx - 4}
                  y={TOPO_CY - r.ry + 27}
                  fill={ring.color}
                  fontSize={7}
                  textAnchor="end"
                  opacity={0.4}
                >
                  {ring.desc}
                </text>
                {/* Surface count badge */}
                {ringCounts[i] > 0 && (
                  <text
                    x={TOPO_CX - r.rx + 12}
                    y={TOPO_CY - r.ry + 16}
                    fill={ring.color}
                    fontSize={8}
                    opacity={0.5}
                  >
                    {ringCounts[i]} surface{ringCounts[i] !== 1 ? 's' : ''}
                  </text>
                )}
              </g>
            );
          })}

          {/* Centerpiece label */}
          <text x={TOPO_CX} y={TOPO_CY - 14} fill="#22c55e" fontSize={11} fontWeight="bold" textAnchor="middle" opacity={0.8}>
            TRUST LAYER
          </text>
          <text x={TOPO_CX} y={TOPO_CY} fill="#4ade80" fontSize={7} textAnchor="middle" opacity={0.5}>
            Receipt Chain · Policy Engine
          </text>
          <text x={TOPO_CX} y={TOPO_CY + 11} fill="#4ade80" fontSize={7} textAnchor="middle" opacity={0.5}>
            Attestation · Hash Anchoring
          </text>
          {surfaces.length === 0 && (
            <text x={TOPO_CX} y={TOPO_CY + 30} fill="#71717a" fontSize={8} textAnchor="middle" opacity={0.6}>
              No surfaces connected
            </text>
          )}

          {/* Surface nodes — distributed around their trust rings */}
          {surfacePositions.map((s) => {
            const tierColors: Record<string, string> = {
              A: '#22c55e', B: '#3b82f6', C: '#f59e0b', D: '#f97316', X: '#ef4444',
            };
            const c = tierColors[s.tier] || '#6b7280';
            return (
              <g key={s.id}>
                <rect
                  x={s.x - 14} y={s.y - 14} width={28} height={28} rx={6}
                  fill={c}
                  fillOpacity={s.isActive ? 0.25 : 0.1}
                  stroke={c}
                  strokeWidth={s.isActive ? 2 : 1}
                  strokeOpacity={s.isActive ? 0.8 : 0.4}
                />
                <text x={s.x} y={s.y + 4} fill={c} fontSize={12} textAnchor="middle">
                  ◈
                </text>
                <text x={s.x} y={s.y + 28} fill={c} fontSize={8} fontWeight="600" textAnchor="middle">
                  {s.name.length > 12 ? s.name.slice(0, 11) + '…' : s.name}
                </text>
                {s.isActive && (
                  <text x={s.x} y={s.y + 37} fill={c} fontSize={6} textAnchor="middle" opacity={0.6}>
                    ACTIVE
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      </div>

      {/* Zoom controls (bottom-right) */}
      <div className="absolute bottom-12 right-4 flex flex-col items-center gap-1">
        <button
          onClick={handleZoomIn}
          className="w-8 h-8 flex items-center justify-center rounded-md bg-gray-800/70 border border-gray-700/50 text-gray-300 hover:bg-gray-700/70 hover:text-white transition-colors text-sm font-bold"
          title="Zoom in"
        >
          +
        </button>
        <button
          onClick={handleReset}
          className="w-8 h-6 flex items-center justify-center rounded-md bg-gray-800/70 border border-gray-700/50 text-gray-500 hover:bg-gray-700/70 hover:text-gray-300 transition-colors text-[9px] font-mono"
          title="Reset zoom"
        >
          {Math.round(zoom * 100)}%
        </button>
        <button
          onClick={handleZoomOut}
          className="w-8 h-8 flex items-center justify-center rounded-md bg-gray-800/70 border border-gray-700/50 text-gray-300 hover:bg-gray-700/70 hover:text-white transition-colors text-sm font-bold"
          title="Zoom out"
        >
          −
        </button>
      </div>

      {/* Legend strip */}
      <div className="flex-shrink-0 flex items-center justify-center gap-6 px-4 py-2 border-t border-gray-800/30 text-[10px]">
        {TRUST_RINGS.slice().reverse().map((ring) => (
          <div key={ring.tier} className="flex items-center gap-1.5">
            <span
              className="w-2.5 h-2.5 rounded-full border"
              style={{ borderColor: ring.color, backgroundColor: ring.bg }}
            />
            <span className="text-gray-400">{ring.tier}</span>
            <span className="text-gray-600">({ring.grade})</span>
          </div>
        ))}
      </div>
    </div>
  );
}
