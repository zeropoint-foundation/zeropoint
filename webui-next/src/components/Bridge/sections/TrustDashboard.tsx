/**
 * TrustDashboard — SOC landing screen
 * 
 * At-a-glance view of trust posture, surfaces, pending approvals,
 * system health, and recent activity. The "home" of ZeroPoint.
 */

import { useBridge } from '../BridgeContext';
import { AGENT_ICONS, AGENT_COLORS, resolveAgentId } from '../types';

function formatTimestamp(ts: number): string {
  const d = new Date(ts);
  const now = Date.now();
  const diff = now - ts;
  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return d.toLocaleDateString();
}

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span className={`inline-block w-2 h-2 rounded-full ${ok ? 'bg-emerald-400' : 'bg-red-400'}`} />
  );
}

export default function TrustDashboard() {
  const { systemStatus, timeline, isConnected, activityEvents } = useBridge();

  const health = systemStatus?.health;
  const metrics = systemStatus?.metrics;

  // Count pending approvals from activity events
  const pendingApprovals = activityEvents.filter(
    e => e.type === 'audit' && e.status === 'pending'
  );

  // Recent timeline events (last 8)
  const recentEvents = timeline.slice(-8).reverse();

  // Surface counts from health data
  const agentCount = health?.agents ?? health?.officers ?? 0;
  const serviceCount = health?.services?.length ?? 0;

  return (
    <div className="flex-1 overflow-y-auto px-8 py-6 space-y-6">
      {/* Section header */}
      <div className="flex items-center gap-2 mb-2">
        <span className="text-lg text-blue-400">◈</span>
        <h2 className="text-sm font-medium text-gray-300 uppercase tracking-wider">Dashboard</h2>
      </div>

      {/* Top row: Trust + Health + Connection */}
      <div className="grid grid-cols-3 gap-4">
        {/* Trust Posture */}
        <div className="bg-gray-800/60 border border-gray-700/50 rounded-lg p-5">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-gray-500 uppercase tracking-wider">Trust Posture</span>
            <StatusDot ok={systemStatus?.trustVerified ?? false} />
          </div>
          <div className="text-2xl font-mono text-emerald-400 mb-1">
            {systemStatus?.trustVerified ? 'VERIFIED' : 'UNVERIFIED'}
          </div>
          <div className="text-xs text-gray-500">
            {systemStatus?.online ? 'System online' : 'System offline'}
          </div>
        </div>

        {/* System Health */}
        <div className="bg-gray-800/60 border border-gray-700/50 rounded-lg p-5">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-gray-500 uppercase tracking-wider">System Health</span>
            <StatusDot ok={health?.overall_status === 'healthy'} />
          </div>
          <div className="text-2xl font-mono text-gray-200 mb-1">
            {health?.overall_status?.toUpperCase() ?? 'UNKNOWN'}
          </div>
          <div className="flex gap-3 text-xs text-gray-500">
            {metrics && (
              <>
                <span>CPU {metrics.cpu}%</span>
                <span>MEM {metrics.memory}</span>
                <span>{metrics.latency}ms</span>
              </>
            )}
          </div>
        </div>

        {/* Connection */}
        <div className="bg-gray-800/60 border border-gray-700/50 rounded-lg p-5">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-gray-500 uppercase tracking-wider">Connection</span>
            <StatusDot ok={isConnected} />
          </div>
          <div className="text-2xl font-mono text-gray-200 mb-1">
            {isConnected ? 'CONNECTED' : 'DISCONNECTED'}
          </div>
          <div className="flex gap-3 text-xs text-gray-500">
            <span>{agentCount} agents</span>
            <span>{serviceCount} services</span>
          </div>
        </div>
      </div>

      {/* Middle row: Surfaces + Pending Approvals */}
      <div className="grid grid-cols-2 gap-4">
        {/* Surfaces */}
        <div className="bg-gray-800/60 border border-gray-700/50 rounded-lg p-5">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-gray-500 uppercase tracking-wider">Surfaces</span>
            <span className="text-xs text-gray-600">{agentCount + serviceCount} total</span>
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-gray-400">Agents</span>
              <span className="font-mono text-gray-200">{agentCount}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-gray-400">Services</span>
              <span className="font-mono text-gray-200">{serviceCount}</span>
            </div>
            {health?.database !== undefined && (
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Database</span>
                <StatusDot ok={health.database} />
              </div>
            )}
          </div>
        </div>

        {/* Pending Approvals */}
        <div className="bg-gray-800/60 border border-gray-700/50 rounded-lg p-5">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-gray-500 uppercase tracking-wider">Pending Approvals</span>
            {pendingApprovals.length > 0 && (
              <span className="text-xs bg-amber-600/30 text-amber-400 px-1.5 py-0.5 rounded">
                {pendingApprovals.length}
              </span>
            )}
          </div>
          {pendingApprovals.length === 0 ? (
            <div className="text-sm text-gray-500 italic">No pending approvals</div>
          ) : (
            <div className="space-y-2">
              {pendingApprovals.slice(0, 4).map(a => (
                <div key={a.id} className="flex items-center gap-2 text-sm">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400 shrink-0" />
                  <span className="text-gray-300 truncate">{a.summary}</span>
                </div>
              ))}
              {pendingApprovals.length > 4 && (
                <div className="text-xs text-gray-500">+{pendingApprovals.length - 4} more</div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-gray-800/60 border border-gray-700/50 rounded-lg p-5">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs text-gray-500 uppercase tracking-wider">Recent Activity</span>
          <span className="text-xs text-gray-600">{timeline.length} total events</span>
        </div>
        {recentEvents.length === 0 ? (
          <div className="text-sm text-gray-500 italic">No activity yet</div>
        ) : (
          <div className="space-y-2">
            {recentEvents.map(event => {
              const aid = resolveAgentId(event);
              const icon = aid ? AGENT_ICONS[aid] : '●';
              const colors = aid ? AGENT_COLORS[aid] : null;
              return (
                <div key={event.id} className="flex items-start gap-2 text-sm">
                  <span className={`shrink-0 ${colors?.accent ?? 'text-gray-500'}`}>{icon}</span>
                  <div className="flex-1 min-w-0">
                    <span className="text-gray-300 line-clamp-1">
                      {event.processEvent?.taskTitle || event.processEvent?.toolName || event.content?.slice(0, 80) || 'Event'}
                    </span>
                  </div>
                  <span className="text-xs text-gray-600 shrink-0">
                    {formatTimestamp(event.timestamp)}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
