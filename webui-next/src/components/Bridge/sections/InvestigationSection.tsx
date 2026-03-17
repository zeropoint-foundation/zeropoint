/**
 * InvestigationSection — Canonical Timeline with Filters
 * 
 * Full timeline of all ZeroPoint activity with category/agent/time
 * filtering and text search. The forensic investigation surface.
 */

import React, { useState, useMemo } from 'react';
import { useBridge } from '../BridgeContext';
import { AGENTS, AGENT_ICONS, AGENT_COLORS, AGENT_ORDER, resolveAgentId } from '../types';
import type { AgentId } from '../types';
import { getTimelineCategory } from '@/types/message';
import type { TimelineCategory } from '@/types/message';

const CATEGORY_COLORS: Record<TimelineCategory, string> = {
  conversation: 'bg-blue-900/30 text-blue-400',
  system: 'bg-gray-800/60 text-gray-400',
  activity: 'bg-teal-900/30 text-teal-400',
  change: 'bg-purple-900/30 text-purple-400',
  milestone: 'bg-amber-900/30 text-amber-400',
};

function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatDate(ts: number): string {
  return new Date(ts).toLocaleDateString([], { month: 'short', day: 'numeric' });
}

export default function InvestigationSection() {
  const { timeline } = useBridge();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategories, setSelectedCategories] = useState<Set<TimelineCategory>>(new Set());
  const [selectedAgents, setSelectedAgents] = useState<Set<AgentId>>(new Set());

  const filteredTimeline = useMemo(() => {
    let events = [...timeline].reverse();

    // Category filter
    if (selectedCategories.size > 0) {
      events = events.filter(m => {
        if (m.processEvent) {
          return selectedCategories.has(getTimelineCategory(m.processEvent.type));
        }
        return selectedCategories.has('conversation');
      });
    }

    // Agent filter
    if (selectedAgents.size > 0) {
      events = events.filter(m => {
        const aid = resolveAgentId(m);
        return aid && selectedAgents.has(aid);
      });
    }

    // Text search
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      events = events.filter(m =>
        m.content?.toLowerCase().includes(q) ||
        m.processEvent?.toolName?.toLowerCase().includes(q) ||
        m.processEvent?.taskTitle?.toLowerCase().includes(q) ||
        m.processEvent?.milestoneTitle?.toLowerCase().includes(q)
      );
    }

    return events;
  }, [timeline, selectedCategories, selectedAgents, searchQuery]);

  const toggleCategory = (cat: TimelineCategory) => {
    setSelectedCategories(prev => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  };

  const toggleAgent = (id: AgentId) => {
    setSelectedAgents(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const categories: TimelineCategory[] = ['conversation', 'activity', 'system', 'change', 'milestone'];

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-2 px-4 pt-4 pb-2">
        <span className="text-lg text-amber-400">◉</span>
        <h2 className="text-sm font-medium text-gray-300 uppercase tracking-wider">Investigation</h2>
        <span className="text-xs text-gray-600 ml-auto">{filteredTimeline.length} events</span>
      </div>

      {/* Filter bar */}
      <div className="px-4 pb-3 space-y-2 border-b border-gray-700/50">
        {/* Search */}
        <input
          type="text"
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          placeholder="Search events..."
          className="w-full px-3 py-1.5 text-xs bg-gray-800/60 border border-gray-700/50 rounded-md text-gray-300 placeholder-gray-600 focus:outline-none focus:border-gray-600"
        />

        {/* Category chips */}
        <div className="flex gap-1 flex-wrap">
          {categories.map(cat => (
            <button
              key={cat}
              onClick={() => toggleCategory(cat)}
              className={`px-2 py-0.5 text-[10px] rounded-full border transition-colors ${
                selectedCategories.has(cat) || selectedCategories.size === 0
                  ? CATEGORY_COLORS[cat] + ' border-current/30'
                  : 'bg-gray-900/40 text-gray-600 border-gray-800'
              }`}
            >
              {cat}
            </button>
          ))}
          <span className="text-gray-700 mx-1">|</span>
          {AGENT_ORDER.map(id => {
            const agent = AGENTS[id];
            const colors = AGENT_COLORS[id];
            const active = selectedAgents.has(id) || selectedAgents.size === 0;
            return (
              <button
                key={id}
                onClick={() => toggleAgent(id)}
                title={agent.name}
                className={`px-2 py-0.5 text-[10px] rounded-full border transition-colors ${
                  active
                    ? `${colors.bg} ${colors.accent} border-current/30`
                    : 'bg-gray-900/40 text-gray-600 border-gray-800'
                }`}
              >
                {AGENT_ICONS[id]} {agent.name}
              </button>
            );
          })}
        </div>
      </div>

      {/* Timeline */}
      <div className="flex-1 overflow-y-auto p-4">
        {filteredTimeline.length === 0 ? (
          <div className="text-sm text-gray-500 italic text-center py-8">
            {timeline.length === 0 ? 'No events recorded' : 'No events match filters'}
          </div>
        ) : (
          <div className="space-y-1">
            {filteredTimeline.slice(0, 200).map((event, idx) => {
              const pe = event.processEvent;
              const cat = pe ? getTimelineCategory(pe.type) : 'conversation';
              const aid = resolveAgentId(event);
              const icon = aid ? AGENT_ICONS[aid] : event.role === 'user' ? '▸' : '●';
              const colors = aid ? AGENT_COLORS[aid] : null;

              // Show date separator
              const prevEvent = idx > 0 ? filteredTimeline[idx - 1] : null;
              const showDate = !prevEvent || formatDate(event.timestamp) !== formatDate(prevEvent.timestamp);

              return (
                <React.Fragment key={event.id}>
                  {showDate && (
                    <div className="text-[10px] text-gray-600 uppercase tracking-wider py-2 mt-2 first:mt-0">
                      {formatDate(event.timestamp)}
                    </div>
                  )}
                  <div className="flex items-start gap-2 py-1.5 border-b border-gray-800/30 hover:bg-gray-800/20 rounded px-1">
                    <span className={`text-sm shrink-0 ${colors?.accent ?? 'text-gray-500'}`}>{icon}</span>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs text-gray-300 line-clamp-2">
                        {pe?.milestoneTitle || pe?.toolName || pe?.taskTitle || event.content?.slice(0, 120) || pe?.type || 'Event'}
                      </div>
                      {pe?.stepDescription && (
                        <div className="text-[10px] text-gray-500 mt-0.5">{pe.stepDescription}</div>
                      )}
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      <span className={`text-[10px] px-1 py-0.5 rounded ${CATEGORY_COLORS[cat]}`}>
                        {cat.slice(0, 4)}
                      </span>
                      <span className="text-[10px] text-gray-600">{formatTime(event.timestamp)}</span>
                    </div>
                  </div>
                </React.Fragment>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
