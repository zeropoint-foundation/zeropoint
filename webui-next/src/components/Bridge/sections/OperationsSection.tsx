/**
 * OperationsSection — Topology, Activity, Tools, Tasks
 *
 * Live view of what ZeroPoint is doing right now: system topology,
 * tool calls, MCP invocations, task progress, and deployments.
 */

import { useState, lazy, Suspense } from 'react';
import { useBridge } from '../BridgeContext';
import { AGENT_ICONS, AGENT_COLORS, resolveAgentId } from '../types';
import type { AgentId } from '../types';
import { getTimelineCategory } from '@/types/message';

// Lazy-load MapStation to avoid pulling in @xyflow/react upfront
const MapStation = lazy(() => import('../stations/MapStation'));

type SubTab = 'topology' | 'activity' | 'tools' | 'tasks';

function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export default function OperationsSection() {
  const { timeline, systemStatus } = useBridge();
  const [activeTab, setActiveTab] = useState<SubTab>('topology');

  // Activity feed: tool calls, handoffs, skill invocations
  const activityEvents = timeline.filter(m => {
    if (!m.processEvent) return false;
    const cat = getTimelineCategory(m.processEvent.type);
    return cat === 'activity';
  }).reverse();

  // Tool events specifically
  const toolEvents = activityEvents.filter(m =>
    m.processEvent?.type === 'tool_call' || m.processEvent?.type === 'mcp_call' || m.processEvent?.type === 'tool_result'
  );

  // Task events
  const taskEvents = activityEvents.filter(m =>
    m.processEvent?.type === 'task_start' || m.processEvent?.type === 'task_progress' ||
    m.processEvent?.type === 'task_complete' || m.processEvent?.type === 'task_failed'
  );

  const health = systemStatus?.health;

  const tabs: { id: SubTab; label: string; count?: number }[] = [
    { id: 'topology', label: 'Topology' },
    { id: 'activity', label: 'Activity', count: activityEvents.length || undefined },
    { id: 'tools', label: 'Tools', count: toolEvents.length || undefined },
    { id: 'tasks', label: 'Tasks', count: taskEvents.length || undefined },
  ];

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-2 px-4 pt-4 pb-2">
        <span className="text-lg text-teal-400">⚙</span>
        <h2 className="text-sm font-medium text-gray-300 uppercase tracking-wider">Operations</h2>
      </div>

      {/* Sub-tabs */}
      <div className="flex gap-1 px-4 pb-3 border-b border-gray-700/50">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-3 py-1.5 text-xs rounded-md transition-colors ${
              activeTab === tab.id
                ? 'bg-gray-700/60 text-gray-200'
                : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/40'
            }`}
          >
            {tab.label}
            {tab.count !== undefined && (
              <span className="ml-1.5 text-[10px] bg-gray-600/40 px-1 py-0.5 rounded">
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-hidden p-4">
        {activeTab === 'topology' && (
          <div className="h-full -m-4">
            <Suspense fallback={
              <div className="flex items-center justify-center h-full text-sm text-gray-500">
                Loading topology...
              </div>
            }>
              <MapStation systemStatus={systemStatus} />
            </Suspense>
          </div>
        )}

        {activeTab === 'activity' && (
          <div className="space-y-1 overflow-y-auto h-full">
            {activityEvents.length === 0 ? (
              <div className="text-sm text-gray-500 italic text-center py-8">No activity recorded</div>
            ) : (
              activityEvents.slice(0, 100).map(event => {
                const pe = event.processEvent!;
                const aid = resolveAgentId({ agentId: event.agentId ?? pe.agentId, officer: event.officer ?? pe.officer });
                const icon = aid ? AGENT_ICONS[aid] : '●';
                const colors = aid ? AGENT_COLORS[aid] : null;
                return (
                  <div key={event.id} className="flex items-start gap-2 py-2 border-b border-gray-800/50">
                    <span className={`text-sm shrink-0 ${colors?.accent ?? 'text-gray-500'}`}>{icon}</span>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs text-gray-300">
                        {pe.toolName || pe.skillName || pe.taskTitle || pe.type}
                      </div>
                      {pe.stepDescription && (
                        <div className="text-[10px] text-gray-500 mt-0.5">{pe.stepDescription}</div>
                      )}
                      {pe.progress !== undefined && (
                        <div className="mt-1 h-1 bg-gray-700 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-teal-500 rounded-full transition-all"
                            style={{ width: `${pe.progress}%` }}
                          />
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {pe.status && (
                        <span className={`w-1.5 h-1.5 rounded-full ${
                          pe.status === 'success' ? 'bg-emerald-400' :
                          pe.status === 'error' ? 'bg-red-400' :
                          'bg-yellow-400'
                        }`} />
                      )}
                      <span className="text-[10px] text-gray-600">{formatTime(event.timestamp)}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        )}

        {activeTab === 'tools' && (
          <div className="space-y-3">
            {/* Services from health */}
            {health?.services && health.services.length > 0 && (
              <div className="mb-4">
                <div className="text-xs text-gray-500 uppercase tracking-wider mb-2">Services</div>
                <div className="grid grid-cols-2 gap-2">
                  {health.services.map((svc: any, i: number) => (
                    <div key={i} className="bg-gray-800/60 border border-gray-700/50 rounded p-2 flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${svc.healthy !== false ? 'bg-emerald-400' : 'bg-red-400'}`} />
                      <span className="text-xs text-gray-300">{svc.name || `Service ${i + 1}`}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Tool call history */}
            <div className="text-xs text-gray-500 uppercase tracking-wider mb-2">Recent Tool Calls</div>
            {toolEvents.length === 0 ? (
              <div className="text-sm text-gray-500 italic text-center py-4">No tool calls recorded</div>
            ) : (
              <div className="space-y-1">
                {toolEvents.slice(0, 50).map(event => {
                  const pe = event.processEvent!;
                  return (
                    <div key={event.id} className="flex items-center gap-2 py-1.5 border-b border-gray-800/50">
                      <span className={`w-1.5 h-1.5 rounded-full ${
                        pe.status === 'success' ? 'bg-emerald-400' :
                        pe.status === 'error' ? 'bg-red-400' :
                        'bg-yellow-400'
                      }`} />
                      <span className="text-xs text-gray-300 font-mono">{pe.toolName ?? 'unknown'}</span>
                      <span className="text-[10px] text-gray-600 ml-auto">{formatTime(event.timestamp)}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {activeTab === 'tasks' && (
          <div className="space-y-2">
            {taskEvents.length === 0 ? (
              <div className="text-sm text-gray-500 italic text-center py-8">No tasks recorded</div>
            ) : (
              taskEvents.slice(0, 50).map(event => {
                const pe = event.processEvent!;
                const isComplete = pe.type === 'task_complete';
                const isFailed = pe.type === 'task_failed';
                return (
                  <div key={event.id} className="bg-gray-800/60 border border-gray-700/50 rounded-lg p-3">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-gray-300">{pe.taskTitle || pe.taskId || 'Task'}</span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                        isComplete ? 'bg-emerald-900/30 text-emerald-400' :
                        isFailed ? 'bg-red-900/30 text-red-400' :
                        'bg-yellow-900/30 text-yellow-400'
                      }`}>
                        {isComplete ? 'DONE' : isFailed ? 'FAILED' : 'RUNNING'}
                      </span>
                    </div>
                    {pe.progress !== undefined && (
                      <div className="mt-2 h-1.5 bg-gray-700 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all ${
                            isFailed ? 'bg-red-500' : isComplete ? 'bg-emerald-500' : 'bg-teal-500'
                          }`}
                          style={{ width: `${pe.progress}%` }}
                        />
                      </div>
                    )}
                    {pe.stepDescription && (
                      <div className="text-[10px] text-gray-500 mt-1">{pe.stepDescription}</div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        )}
      </div>
    </div>
  );
}
