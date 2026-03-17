/**
 * TrustSection — Posture Map, Approvals, Audit Log, Attestations
 *
 * Deep-dive into ZeroPoint's security posture. Trust ring topology,
 * HCS approval queue, system audit trail, and trust receipt attestations.
 */

import { useState, useEffect, useCallback, lazy, Suspense } from 'react';
import { useBridge } from '../BridgeContext';
import { AGENT_ICONS, AGENT_COLORS, resolveAgentId } from '../types';
import type { HCSApprovalRequest, HCSApprovalDecision, TrustReceipt } from '../types';
import { getTimelineCategory } from '@/types/message';

const TrustTopologyView = lazy(() => import('./TrustTopologyView'));

type SubTab = 'posture' | 'approvals' | 'audit' | 'attestations';

function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function RiskBadge({ level }: { level: string }) {
  const colors: Record<string, string> = {
    low: 'bg-emerald-900/40 text-emerald-400 border-emerald-700/40',
    medium: 'bg-yellow-900/40 text-yellow-400 border-yellow-700/40',
    high: 'bg-orange-900/40 text-orange-400 border-orange-700/40',
    critical: 'bg-red-900/40 text-red-400 border-red-700/40',
  };
  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded border ${colors[level] ?? colors.low}`}>
      {level.toUpperCase()}
    </span>
  );
}

export default function TrustSection() {
  const { timeline, subscribe, sendRawMessage } = useBridge();
  const [activeTab, setActiveTab] = useState<SubTab>('posture');
  const [approvals, setApprovals] = useState<HCSApprovalRequest[]>([]);
  const [receipts, setReceipts] = useState<TrustReceipt[]>([]);

  // Subscribe to HCS approval requests
  useEffect(() => {
    const unsub1 = subscribe('HCSApprovalRequest', (data: unknown) => {
      const req = data as HCSApprovalRequest;
      setApprovals(prev => {
        const exists = prev.find(a => a.id === req.id);
        if (exists) return prev;
        return [...prev, req];
      });
    });
    const unsub2 = subscribe('HCSApprovalDecision', (data: unknown) => {
      const dec = data as HCSApprovalDecision;
      setApprovals(prev => prev.filter(a => a.id !== dec.requestId));
    });
    const unsub3 = subscribe('TrustReceipt', (data: unknown) => {
      const receipt = data as TrustReceipt;
      setReceipts(prev => [receipt, ...prev].slice(0, 100));
    });
    return () => { unsub1(); unsub2(); unsub3(); };
  }, [subscribe]);

  const handleApproval = useCallback((requestId: string, decision: 'approved' | 'rejected') => {
    sendRawMessage({
      type: 'HCSApprovalDecision',
      payload: {
        requestId,
        decision,
        decidedBy: 'user',
        decidedAt: Date.now(),
      }
    } as any);
    setApprovals(prev => prev.filter(a => a.id !== requestId));
  }, [sendRawMessage]);

  // Audit log: system + change + milestone events from timeline
  const auditEvents = timeline.filter(m => {
    if (!m.processEvent) return false;
    const cat = getTimelineCategory(m.processEvent.type);
    return cat === 'system' || cat === 'change' || cat === 'milestone';
  }).reverse();

  const tabs: { id: SubTab; label: string; count?: number }[] = [
    { id: 'posture', label: 'Posture Map' },
    { id: 'approvals', label: 'Approvals', count: approvals.length || undefined },
    { id: 'audit', label: 'Audit Log', count: auditEvents.length || undefined },
    { id: 'attestations', label: 'Attestations', count: receipts.length || undefined },
  ];

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-2 px-4 pt-4 pb-2">
        <span className="text-lg text-red-400">⊘</span>
        <h2 className="text-sm font-medium text-gray-300 uppercase tracking-wider">Trust Center</h2>
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
      <div className={`flex-1 ${activeTab === 'posture' ? 'overflow-hidden' : 'overflow-y-auto'} p-4`}>
        {activeTab === 'posture' && (
          <div className="h-full -m-4">
            <Suspense fallback={
              <div className="flex items-center justify-center h-full text-sm text-gray-500">
                Loading posture map...
              </div>
            }>
              <TrustTopologyView />
            </Suspense>
          </div>
        )}

        {activeTab === 'approvals' && (
          <div className="space-y-3">
            {approvals.length === 0 ? (
              <div className="text-sm text-gray-500 italic text-center py-8">No pending approvals</div>
            ) : (
              approvals.map(req => (
                <div key={req.id} className="bg-gray-800/60 border border-gray-700/50 rounded-lg p-4">
                  <div className="flex items-start justify-between mb-2">
                    <div>
                      <div className="text-sm text-gray-200 font-medium">{req.title}</div>
                      <div className="text-xs text-gray-500 mt-0.5">{req.type}</div>
                    </div>
                    <RiskBadge level={req.riskLevel} />
                  </div>
                  <div className="text-xs text-gray-400 mb-3">{req.description}</div>
                  {req.affectedResources && req.affectedResources.length > 0 && (
                    <div className="text-xs text-gray-500 mb-3">
                      Affects: {req.affectedResources.join(', ')}
                    </div>
                  )}
                  <div className="flex gap-2">
                    <button
                      onClick={() => handleApproval(req.id, 'approved')}
                      className="px-3 py-1 text-xs bg-emerald-600/30 text-emerald-400 border border-emerald-700/40 rounded hover:bg-emerald-600/50 transition-colors"
                    >
                      Approve
                    </button>
                    <button
                      onClick={() => handleApproval(req.id, 'rejected')}
                      className="px-3 py-1 text-xs bg-red-600/20 text-red-400 border border-red-700/40 rounded hover:bg-red-600/40 transition-colors"
                    >
                      Reject
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === 'audit' && (
          <div className="space-y-1">
            {auditEvents.length === 0 ? (
              <div className="text-sm text-gray-500 italic text-center py-8">No audit events</div>
            ) : (
              auditEvents.map(event => {
                const pe = event.processEvent!;
                const cat = getTimelineCategory(pe.type);
                const aid = resolveAgentId({ agentId: event.agentId ?? pe.agentId, officer: event.officer ?? pe.officer });
                const icon = aid ? AGENT_ICONS[aid] : '●';
                const colors = aid ? AGENT_COLORS[aid] : null;
                return (
                  <div key={event.id} className="flex items-start gap-2 py-2 border-b border-gray-800/50">
                    <span className={`text-sm shrink-0 ${colors?.accent ?? 'text-gray-500'}`}>{icon}</span>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs text-gray-300">
                        {pe.milestoneTitle || pe.changeDescription || pe.toolName || pe.type}
                      </div>
                      {pe.milestoneDescription && (
                        <div className="text-[10px] text-gray-500 mt-0.5">{pe.milestoneDescription}</div>
                      )}
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className={`text-[10px] px-1 py-0.5 rounded ${
                        cat === 'milestone' ? 'bg-purple-900/30 text-purple-400' :
                        cat === 'change' ? 'bg-blue-900/30 text-blue-400' :
                        'bg-gray-800/60 text-gray-500'
                      }`}>{cat}</span>
                      <span className="text-[10px] text-gray-600">{formatTime(event.timestamp)}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        )}

        {activeTab === 'attestations' && (
          <div className="space-y-2">
            {receipts.length === 0 ? (
              <div className="text-sm text-gray-500 italic text-center py-8">No trust receipts recorded</div>
            ) : (
              receipts.map(receipt => (
                <div key={receipt.id} className="bg-gray-800/60 border border-gray-700/50 rounded-lg p-3">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs text-gray-300 font-mono">{receipt.operationType}</span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                      receipt.success ? 'bg-emerald-900/30 text-emerald-400' : 'bg-red-900/30 text-red-400'
                    }`}>
                      {receipt.success ? 'PASS' : 'FAIL'}
                    </span>
                  </div>
                  <div className="text-[10px] text-gray-500 font-mono truncate">
                    Hash: {receipt.operationHash?.slice(0, 16)}...
                  </div>
                  <div className="text-[10px] text-gray-600 mt-1">
                    {formatTime(receipt.timestamp)} · Signer: {receipt.signerId ?? 'unknown'}
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}
