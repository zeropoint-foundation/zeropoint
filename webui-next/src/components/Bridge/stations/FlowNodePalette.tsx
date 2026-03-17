/**
 * FlowNodePalette — Draggable node palette for flow authoring
 *
 * Grouped by category (Core, Trust, Evidence) and filterable by agent.
 * Nodes are dragged onto the React Flow canvas to add to the flow graph.
 * Agent templates provide one-click pre-built flow patterns.
 */

import React, { useState, useMemo } from 'react';
import {
  NODE_TEMPLATES,
  getTemplatesByAgent,
  getAgentTemplates,
  wireTemplateEdges,
} from '@/services/FlowNodeRegistry';
import type { ZPNodeTemplate, AgentFlowTemplate, ZPFlowNode, ZPFlowEdge } from '@/types/zpflow';
import type { AgentId } from '../types';
import { AGENTS, AGENT_ORDER, AGENT_ICONS } from '../types';

interface FlowNodePaletteProps {
  /** Called when user drags a node template onto the canvas */
  onDropNode: (template: ZPNodeTemplate, position: { x: number; y: number }) => void;
  /** Called when user selects an agent template */
  onApplyTemplate: (nodes: ZPFlowNode[], edges: ZPFlowEdge[]) => void;
}

type PaletteTab = 'nodes' | 'templates';

const CATEGORY_META = {
  core: { label: 'Core', color: '#3b82f6', description: 'Execution & routing' },
  trust: { label: 'Trust', color: '#ef4444', description: 'Security & policy' },
  evidence: { label: 'Evidence', color: '#f97316', description: 'Observability' },
  control: { label: 'Control', color: '#dc2626', description: 'Human-in-loop (ZT §1.9)' },
  vault: { label: 'Vault', color: '#7c3aed', description: 'Dynamic credentials (ZT §1.1)' },
  segment: { label: 'Segment', color: '#0891b2', description: 'Micro-segmentation (ZT §1.2)' },
} as const;

const FlowNodePalette: React.FC<FlowNodePaletteProps> = ({ onDropNode: _onDropNode, onApplyTemplate }) => {
  const [tab, setTab] = useState<PaletteTab>('nodes');
  const [filterAgent, setFilterAgent] = useState<AgentId | null>(null);
  const [expandedCategory, setExpandedCategory] = useState<string | null>('core');

  const agentTemplates = useMemo(() => getAgentTemplates(), []);

  const filteredTemplates = useMemo(() => {
    if (!filterAgent) return NODE_TEMPLATES;
    return getTemplatesByAgent(filterAgent);
  }, [filterAgent]);

  const categories = useMemo(() => {
    const grouped: Record<string, ZPNodeTemplate[]> = { core: [], trust: [], evidence: [], control: [], vault: [], segment: [] };
    filteredTemplates.forEach(t => {
      if (grouped[t.category]) grouped[t.category].push(t);
    });
    return grouped;
  }, [filteredTemplates]);

  /** Handle drag start — store template data for drop handler */
  const onDragStart = (e: React.DragEvent, template: ZPNodeTemplate) => {
    e.dataTransfer.setData('application/zpflow-node', JSON.stringify(template));
    e.dataTransfer.effectAllowed = 'move';
  };

  /** Apply an agent template */
  const handleApplyTemplate = (template: AgentFlowTemplate) => {
    const edges = wireTemplateEdges(template);
    onApplyTemplate(template.nodes, edges);
  };

  return (
    <div className="w-56 flex-shrink-0 border-r border-gray-800 bg-gray-900/80 flex flex-col overflow-hidden">
      {/* Tab Bar */}
      <div className="flex border-b border-gray-800">
        <button
          onClick={() => setTab('nodes')}
          className={`flex-1 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider transition-colors ${
            tab === 'nodes' ? 'text-cyan-400 border-b-2 border-cyan-400' : 'text-gray-500 hover:text-gray-300'
          }`}
        >
          Nodes
        </button>
        <button
          onClick={() => setTab('templates')}
          className={`flex-1 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider transition-colors ${
            tab === 'templates' ? 'text-cyan-400 border-b-2 border-cyan-400' : 'text-gray-500 hover:text-gray-300'
          }`}
        >
          Agents
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        {tab === 'nodes' ? (
          <div className="p-2 space-y-1">
            {/* Agent Filter */}
            <div className="flex items-center gap-1 px-2 py-1.5 mb-2">
              <button
                onClick={() => setFilterAgent(null)}
                className={`px-2 py-0.5 text-[9px] rounded transition-colors ${
                  !filterAgent ? 'bg-cyan-900/50 text-cyan-300' : 'text-gray-500 hover:text-gray-300'
                }`}
              >
                All
              </button>
              {AGENT_ORDER.map(id => (
                <button
                  key={id}
                  onClick={() => setFilterAgent(filterAgent === id ? null : id)}
                  className={`px-1.5 py-0.5 text-[9px] rounded transition-colors ${
                    filterAgent === id ? 'bg-cyan-900/50 text-cyan-300' : 'text-gray-500 hover:text-gray-300'
                  }`}
                  title={AGENTS[id].name}
                >
                  {AGENT_ICONS[id]}
                </button>
              ))}
            </div>

            {/* Categories */}
            {(Object.keys(CATEGORY_META) as Array<keyof typeof CATEGORY_META>).map(cat => (
              <div key={cat}>
                <button
                  onClick={() => setExpandedCategory(expandedCategory === cat ? null : cat)}
                  className="w-full flex items-center gap-2 px-2 py-1.5 text-[10px] font-semibold uppercase tracking-wider hover:bg-gray-800/50 rounded transition-colors"
                  style={{ color: CATEGORY_META[cat].color }}
                >
                  <span className="text-[8px]">{expandedCategory === cat ? '▼' : '▶'}</span>
                  {CATEGORY_META[cat].label}
                  <span className="ml-auto text-gray-600 font-normal normal-case">{categories[cat]?.length || 0}</span>
                </button>

                {expandedCategory === cat && categories[cat]?.map(tpl => (
                  <div
                    key={tpl.type}
                    draggable
                    onDragStart={(e) => onDragStart(e, tpl)}
                    className="flex items-center gap-2 px-3 py-2 ml-3 text-xs cursor-grab active:cursor-grabbing hover:bg-gray-800/70 rounded transition-colors group"
                    title={tpl.description}
                  >
                    <span className="flex-shrink-0 w-5 text-center" style={{ color: tpl.color }}>{tpl.icon}</span>
                    <div className="flex-1 min-w-0">
                      <div className="text-gray-300 group-hover:text-white truncate">{tpl.label}</div>
                      <div className="text-[9px] text-gray-600 truncate">{tpl.type}</div>
                    </div>
                    {tpl.agentAffinity && (
                      <span className="text-[9px] text-gray-600" title={AGENTS[tpl.agentAffinity].name}>
                        {AGENT_ICONS[tpl.agentAffinity]}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            ))}
          </div>
        ) : (
          /* Agent Templates Tab */
          <div className="p-2 space-y-2">
            {agentTemplates.map(tpl => (
              <button
                key={tpl.id}
                onClick={() => handleApplyTemplate(tpl)}
                className="w-full text-left p-3 rounded-lg border border-gray-800 hover:border-gray-600 hover:bg-gray-800/50 transition-all group"
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-sm">{AGENT_ICONS[tpl.agent]}</span>
                  <span className="text-xs font-semibold text-gray-200 group-hover:text-white">{tpl.name}</span>
                </div>
                <div className="text-[10px] text-gray-500 leading-relaxed">{tpl.description}</div>
                <div className="flex gap-1 mt-2 flex-wrap">
                  {tpl.tags.map(tag => (
                    <span key={tag} className="text-[8px] px-1.5 py-0.5 bg-gray-800 text-gray-500 rounded">
                      {tag}
                    </span>
                  ))}
                </div>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default FlowNodePalette;
