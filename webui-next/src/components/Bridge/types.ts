/**
 * Bridge type definitions — single source of truth for the SOC Dashboard.
 *
 * Agents, sections, timeline messages, HCS approvals, trust receipts,
 * process events, system status, and voice modes.
 */

// ── Section Navigation ──────────────────────────────────────────────
export type SectionId = 'dashboard' | 'trust' | 'operations' | 'investigation' | 'settings';

// ── Agent System ────────────────────────────────────────────────────
export type AgentId = 'atlas' | 'aegis' | 'themis' | 'sparky' | 'echo';

export const AGENTS: Record<AgentId, { name: string; title: string }> = {
  atlas: { name: 'Atlas', title: 'Architect' },
  aegis: { name: 'Aegis', title: 'Security' },
  themis: { name: 'Themis', title: 'Governance' },
  sparky: { name: 'Sparky', title: 'Engineer' },
  echo: { name: 'Echo', title: 'Concierge' },
};

export const AGENT_ICONS: Record<AgentId, string> = {
  atlas: '◈',
  aegis: '⊘',
  themis: '⚖',
  sparky: '⚙',
  echo: '◉',
};

export const AGENT_COLORS: Record<AgentId, { bg: string; accent: string }> = {
  atlas: { bg: 'bg-blue-900/40', accent: 'text-blue-400' },
  aegis: { bg: 'bg-red-900/40', accent: 'text-red-400' },
  themis: { bg: 'bg-purple-900/40', accent: 'text-purple-400' },
  sparky: { bg: 'bg-teal-900/40', accent: 'text-teal-400' },
  echo: { bg: 'bg-amber-900/40', accent: 'text-amber-400' },
};

export const AGENT_ORDER: AgentId[] = ['atlas', 'aegis', 'themis', 'sparky', 'echo'];

// Backward-compatible aliases (for gradual migration of server protocol)
/** @deprecated Use AgentId */
export type OfficerId = AgentId;
/** @deprecated Use AGENTS */
export const OFFICERS = AGENTS;
/** @deprecated Use AGENT_ICONS */
export const OFFICER_ICONS = AGENT_ICONS;
/** @deprecated Use AGENT_COLORS */
export const OFFICER_COLORS = AGENT_COLORS;
/** @deprecated Use AGENT_ORDER */
export const OFFICER_ORDER = AGENT_ORDER;

// ── HCS Approval Types ──────────────────────────────────────────────
export interface HCSApprovalRequest {
  id: string;
  title: string;
  type: string;
  description: string;
  riskLevel: string;
  affectedResources?: string[];
}

export interface HCSApprovalDecision {
  requestId: string;
  decision: 'approved' | 'rejected';
  decidedBy: string;
  decidedAt: number;
}

// ── Trust Receipts ──────────────────────────────────────────────────
export interface TrustReceipt {
  id: string;
  operationType: string;
  operationHash?: string;
  success: boolean;
  timestamp: number;
  signerId?: string;
}

// ── Process Events ──────────────────────────────────────────────────
export interface ProcessEvent {
  type: string;
  toolName?: string;
  taskTitle?: string;
  taskId?: string;
  skillName?: string;
  milestoneTitle?: string;
  milestoneDescription?: string;
  changeDescription?: string;
  stepDescription?: string;
  progress?: number;
  status?: string;
  agentId?: string;
  /** @deprecated Server still sends 'officer'; prefer agentId */
  officer?: string;
}

// ── Timeline Messages ───────────────────────────────────────────────
export interface TimelineMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content?: string;
  /** Agent that produced this message */
  agentId?: string;
  /** @deprecated Server still sends 'officer'; prefer agentId */
  officer?: string;
  timestamp: number;
  processEvent?: ProcessEvent;
}

// ── Activity Events ─────────────────────────────────────────────────
export interface ActivityEvent {
  id: string;
  type: string;
  status?: string;
  summary: string;
  timestamp: number;
}

// ── System Status ───────────────────────────────────────────────────
export interface HealthData {
  overall_status?: string;
  agents?: number;
  /** @deprecated Use agents */
  officers?: number;
  services?: any[];
  database?: boolean;
}

export interface MetricsData {
  cpu?: number;
  memory?: string;
  latency?: number;
}

export interface SystemStatus {
  trustVerified?: boolean;
  online?: boolean;
  health?: HealthData;
  metrics?: MetricsData;
}

// ── Voice Modes ─────────────────────────────────────────────────────
export type VoiceResponseMode = 'always_voice' | 'always_text' | 'voice_and_text' | 'match_input';

// ── Helpers ─────────────────────────────────────────────────────────
/** Type guard to check if a string is a valid AgentId */
export function isAgentId(s: string | undefined | null): s is AgentId {
  return s != null && ['atlas', 'aegis', 'themis', 'sparky', 'echo'].includes(s);
}

/** Resolve agent ID from a message (server may send as officer or agentId) */
export function resolveAgentId(msg: { agentId?: string; officer?: string }): AgentId | undefined {
  const id = msg.agentId || msg.officer;
  return isAgentId(id) ? id : undefined;
}
