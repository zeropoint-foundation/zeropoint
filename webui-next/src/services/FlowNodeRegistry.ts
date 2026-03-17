/**
 * FlowNodeRegistry — Node templates and agent flow patterns
 *
 * Central registry of all node types available in the flow canvas.
 * Each node type has default ports, config, and agent affinity.
 * Agents provide pre-built flow templates that users can drag onto canvas.
 */

import type {
  ZPNodeTemplate,
  ZPFlowPort,
  AgentFlowTemplate,
  ZPFlowNode,
  ZPFlowEdge,
} from '../types/zpflow';
import type { AgentId } from '../components/Bridge/types';

// =============================================================================
// DEFAULT PORTS
// =============================================================================

const INPUT_PORT: ZPFlowPort = { id: 'in', label: 'Input', type: 'input', dataType: 'json' };
const OUTPUT_PORT: ZPFlowPort = { id: 'out', label: 'Output', type: 'output', dataType: 'json' };
const PASS_PORT: ZPFlowPort = { id: 'pass', label: 'Pass', type: 'output', dataType: 'json' };
const FAIL_PORT: ZPFlowPort = { id: 'fail', label: 'Fail', type: 'output', dataType: 'json' };

// =============================================================================
// NODE TEMPLATES
// =============================================================================

export const NODE_TEMPLATES: ZPNodeTemplate[] = [
  // ── Core Execution ──
  { type: 'Data.Input', label: 'Input', description: 'Flow entry point', category: 'core',
    defaultPorts: [OUTPUT_PORT], defaultConfig: { schema: 'any' }, icon: '▶', color: '#3b82f6' },
  { type: 'Data.Output', label: 'Output', description: 'Flow exit point', category: 'core',
    defaultPorts: [INPUT_PORT], defaultConfig: { schema: 'any' }, icon: '◀', color: '#ec4899' },
  { type: 'Model.Invoke', label: 'Model Call', description: 'Invoke an LLM model', category: 'core',
    defaultPorts: [INPUT_PORT, OUTPUT_PORT], defaultConfig: { model: 'default', maxTokens: 4096 },
    agentAffinity: 'atlas', icon: '◇', color: '#8b5cf6' },
  { type: 'Tool.HTTP', label: 'HTTP Call', description: 'External API request', category: 'core',
    defaultPorts: [INPUT_PORT, OUTPUT_PORT], defaultConfig: { method: 'GET', url: '', headers: {} },
    agentAffinity: 'sparky', icon: '⚡', color: '#f59e0b' },
  { type: 'Tool.Execute', label: 'Tool Exec', description: 'Execute a local tool', category: 'core',
    defaultPorts: [INPUT_PORT, OUTPUT_PORT], defaultConfig: { tool: '', args: {} },
    agentAffinity: 'sparky', icon: '⚙', color: '#f59e0b' },
  { type: 'Transform.Map', label: 'Map', description: 'Transform data shape', category: 'core',
    defaultPorts: [INPUT_PORT, OUTPUT_PORT], defaultConfig: { expression: '' }, icon: '↦', color: '#10b981' },
  { type: 'Transform.Filter', label: 'Filter', description: 'Filter data by condition', category: 'core',
    defaultPorts: [INPUT_PORT, PASS_PORT, FAIL_PORT], defaultConfig: { condition: '' }, icon: '⊳', color: '#10b981' },
  { type: 'Route.Switch', label: 'Switch', description: 'Conditional branching', category: 'core',
    defaultPorts: [INPUT_PORT, { id: 'branch_a', label: 'A', type: 'output' }, { id: 'branch_b', label: 'B', type: 'output' }],
    defaultConfig: { condition: '' }, agentAffinity: 'atlas', icon: '⬡', color: '#8b5cf6' },
  { type: 'Route.Parallel', label: 'Parallel', description: 'Fan-out parallel execution', category: 'core',
    defaultPorts: [INPUT_PORT, { id: 'out_1', label: 'Out 1', type: 'output' }, { id: 'out_2', label: 'Out 2', type: 'output' }],
    defaultConfig: { strategy: 'all' }, icon: '⇉', color: '#8b5cf6' },
  { type: 'Route.Join', label: 'Join', description: 'Fan-in merge', category: 'core',
    defaultPorts: [{ id: 'in_1', label: 'In 1', type: 'input' }, { id: 'in_2', label: 'In 2', type: 'input' }, OUTPUT_PORT],
    defaultConfig: { strategy: 'all' }, icon: '⇇', color: '#8b5cf6' },

  // ── Trust & Safety ──
  { type: 'Guard.PII', label: 'PII Guard', description: 'Detect & redact PII', category: 'trust',
    defaultPorts: [INPUT_PORT, PASS_PORT, FAIL_PORT], defaultConfig: { action: 'redact', patterns: ['email', 'phone', 'ssn'] },
    agentAffinity: 'aegis', icon: '🛡', color: '#ef4444' },
  { type: 'Guard.Injection', label: 'Injection Guard', description: 'Prompt injection defense', category: 'trust',
    defaultPorts: [INPUT_PORT, PASS_PORT, FAIL_PORT], defaultConfig: { sensitivity: 'high' },
    agentAffinity: 'aegis', icon: '⊘', color: '#ef4444' },
  { type: 'Guard.Content', label: 'Content Guard', description: 'Content safety filter', category: 'trust',
    defaultPorts: [INPUT_PORT, PASS_PORT, FAIL_PORT], defaultConfig: { categories: ['harmful', 'illegal'] },
    agentAffinity: 'aegis', icon: '⚑', color: '#ef4444' },
  { type: 'Policy.Check', label: 'Policy Check', description: 'Non-blocking policy evaluation', category: 'trust',
    defaultPorts: [INPUT_PORT, OUTPUT_PORT], defaultConfig: { policy: '' },
    agentAffinity: 'themis', icon: '⚖', color: '#a855f7' },
  { type: 'Policy.Gate', label: 'Policy Gate', description: 'Blocking policy enforcement', category: 'trust',
    defaultPorts: [INPUT_PORT, PASS_PORT, FAIL_PORT], defaultConfig: { policy: '', requireApproval: false },
    agentAffinity: 'themis', icon: '⊞', color: '#a855f7' },
  { type: 'Trust.Boundary', label: 'Trust Boundary', description: 'Trust tier transition', category: 'trust',
    defaultPorts: [INPUT_PORT, OUTPUT_PORT], defaultConfig: { fromTier: 'D', toTier: 'C' },
    agentAffinity: 'aegis', icon: '◈', color: '#ef4444' },
  { type: 'Trust.Attest', label: 'Attestation', description: 'Generate trust attestation', category: 'trust',
    defaultPorts: [INPUT_PORT, OUTPUT_PORT], defaultConfig: { algorithm: 'ed25519' },
    agentAffinity: 'themis', icon: '✦', color: '#a855f7' },
  { type: 'Auth.Verify', label: 'Auth Verify', description: 'Verify capability/identity', category: 'trust',
    defaultPorts: [INPUT_PORT, PASS_PORT, FAIL_PORT], defaultConfig: { requiredCaps: [] },
    agentAffinity: 'aegis', icon: '🔑', color: '#ef4444' },

  // ── Evidence & Observability ──
  { type: 'Trace.Emit', label: 'Trace', description: 'Emit structured trace event', category: 'evidence',
    defaultPorts: [INPUT_PORT, OUTPUT_PORT], defaultConfig: { level: 'info' },
    agentAffinity: 'echo', icon: '◉', color: '#f97316' },
  { type: 'Trace.Span', label: 'Span', description: 'Create trace span', category: 'evidence',
    defaultPorts: [INPUT_PORT, OUTPUT_PORT], defaultConfig: { name: '' },
    agentAffinity: 'echo', icon: '⊙', color: '#f97316' },
  { type: 'Artifact.Store', label: 'Store Artifact', description: 'Store with integrity hash', category: 'evidence',
    defaultPorts: [INPUT_PORT, OUTPUT_PORT], defaultConfig: { storage: 'local' },
    agentAffinity: 'echo', icon: '📁', color: '#f97316' },
  { type: 'Audit.Commit', label: 'Audit Log', description: 'Commit to audit ledger', category: 'evidence',
    defaultPorts: [INPUT_PORT, OUTPUT_PORT], defaultConfig: { ledger: 'default' },
    agentAffinity: 'themis', icon: '📋', color: '#a855f7' },
  { type: 'Monitor.Metric', label: 'Metric', description: 'Emit metric observation', category: 'evidence',
    defaultPorts: [INPUT_PORT, OUTPUT_PORT], defaultConfig: { name: '', unit: '' },
    agentAffinity: 'echo', icon: '📊', color: '#f97316' },
  { type: 'Monitor.Alert', label: 'Alert', description: 'Trigger alert condition', category: 'evidence',
    defaultPorts: [INPUT_PORT, OUTPUT_PORT], defaultConfig: { severity: 'warning', channel: 'default' },
    agentAffinity: 'echo', icon: '🔔', color: '#f97316' },

  // ── Control (ZT §1.9 — Human in the Loop) ──
  { type: 'Control.KillSwitch', label: 'Kill Switch', description: 'Emergency halt flow execution (ZT §1.9.1)', category: 'control',
    defaultPorts: [INPUT_PORT, PASS_PORT, FAIL_PORT], defaultConfig: { condition: 'manual', cooldownMs: 5000 },
    agentAffinity: 'aegis', icon: '⏹', color: '#dc2626' },
  { type: 'Control.Throttle', label: 'Throttle', description: 'Rate-limit activity (ZT §1.9.2)', category: 'control',
    defaultPorts: [INPUT_PORT, PASS_PORT, FAIL_PORT], defaultConfig: { maxPerMinute: 60, burstLimit: 10 },
    agentAffinity: 'themis', icon: '⏱', color: '#dc2626' },
  { type: 'Control.HumanApproval', label: 'Human Approval', description: 'Block until human approves', category: 'control',
    defaultPorts: [INPUT_PORT, PASS_PORT, FAIL_PORT], defaultConfig: { approver: '', timeoutMs: 300000 },
    agentAffinity: 'themis', icon: '👤', color: '#dc2626' },
  { type: 'Control.Canary', label: 'Canary Gate', description: 'Canary deployment gate (ZT §1.9.3)', category: 'control',
    defaultPorts: [INPUT_PORT, { id: 'canary', label: 'Canary', type: 'output' }, { id: 'stable', label: 'Stable', type: 'output' }],
    defaultConfig: { canaryPercent: 5, promoteThreshold: 0.99, rollbackThreshold: 0.95 },
    agentAffinity: 'echo', icon: '🐤', color: '#dc2626' },
  { type: 'Control.CircuitBreaker', label: 'Circuit Breaker', description: 'Open circuit on failure threshold', category: 'control',
    defaultPorts: [INPUT_PORT, PASS_PORT, FAIL_PORT], defaultConfig: { failureThreshold: 5, resetTimeoutMs: 30000, halfOpenMax: 1 },
    agentAffinity: 'aegis', icon: '⚡', color: '#dc2626' },

  // ── Vault (ZT §1.1.4, §1.1.5 — Dynamic Credentials) ──
  { type: 'Vault.Fetch', label: 'Vault Fetch', description: 'Fetch dynamic credential from encrypted store', category: 'vault',
    defaultPorts: [INPUT_PORT, OUTPUT_PORT], defaultConfig: { secretKey: '', provider: '' },
    agentAffinity: 'aegis', icon: '🔐', color: '#7c3aed' },
  { type: 'Vault.Rotate', label: 'Vault Rotate', description: 'Trigger credential rotation', category: 'vault',
    defaultPorts: [INPUT_PORT, OUTPUT_PORT], defaultConfig: { secretKey: '', rotationPolicy: 'strict' },
    agentAffinity: 'aegis', icon: '🔄', color: '#7c3aed' },
  { type: 'Vault.Lease', label: 'Vault Lease', description: 'Acquire time-bound credential lease (ZT §5.3.3)', category: 'vault',
    defaultPorts: [INPUT_PORT, OUTPUT_PORT], defaultConfig: { secretKey: '', ttlSeconds: 300, provider: '' },
    agentAffinity: 'aegis', icon: '⏳', color: '#7c3aed' },
  { type: 'Vault.Revoke', label: 'Vault Revoke', description: 'Revoke credential immediately', category: 'vault',
    defaultPorts: [INPUT_PORT, OUTPUT_PORT], defaultConfig: { leaseId: '', reason: '' },
    agentAffinity: 'aegis', icon: '🚫', color: '#7c3aed' },

  // ── Segmentation (ZT §1.2.1 — Micro-segmentation) ──
  { type: 'Segment.Boundary', label: 'Segment Boundary', description: 'Micro-segment isolation boundary (ZT §1.2.1)', category: 'segment',
    defaultPorts: [INPUT_PORT, OUTPUT_PORT], defaultConfig: { segmentId: '', isolationLevel: 'strict' },
    agentAffinity: 'aegis', icon: '🧱', color: '#0891b2' },
  { type: 'Segment.Encrypt', label: 'Segment Encrypt', description: 'Encrypt data crossing segment (ZT §1.4.1)', category: 'segment',
    defaultPorts: [INPUT_PORT, OUTPUT_PORT], defaultConfig: { algorithm: 'chacha20-poly1305', keySource: 'vault' },
    agentAffinity: 'aegis', icon: '🔒', color: '#0891b2' },
];

/** Look up a template by node type */
export function getNodeTemplate(type: string): ZPNodeTemplate | undefined {
  return NODE_TEMPLATES.find(t => t.type === type);
}

/** Get templates filtered by category */
export function getTemplatesByCategory(category: 'core' | 'trust' | 'evidence' | 'control' | 'vault' | 'segment'): ZPNodeTemplate[] {
  return NODE_TEMPLATES.filter(t => t.category === category);
}

/** Get templates by agent affinity */
export function getTemplatesByAgent(agent: AgentId): ZPNodeTemplate[] {
  return NODE_TEMPLATES.filter(t => t.agentAffinity === agent);
}

// =============================================================================
// AGENT FLOW TEMPLATES — Pre-built patterns
// =============================================================================

/** Create a unique node ID */
let _nodeCounter = 0;
function nodeId(): string { return `n_${Date.now()}_${++_nodeCounter}`; }
function edgeId(): string { return `e_${Date.now()}_${++_nodeCounter}`; }

/** Helper to make a ZPFlowNode from a template */
function makeNode(
  type: ZPNodeTemplate['type'],
  label: string,
  x: number, y: number,
  configOverrides?: Record<string, unknown>,
): ZPFlowNode {
  const tpl = getNodeTemplate(type);
  if (!tpl) throw new Error(`Unknown node type: ${type}`);
  return {
    id: nodeId(),
    type: tpl.type,
    label,
    position: { x, y },
    config: { ...tpl.defaultConfig, ...configOverrides },
    ports: [...tpl.defaultPorts],
    agentOrigin: tpl.agentAffinity,
  };
}

/** Build agent flow templates */
export function getAgentTemplates(): AgentFlowTemplate[] {
  return [
    // ── Atlas: Routing & Orchestration ──
    {
      id: 'atlas-router',
      name: 'Atlas Router',
      description: 'Input → Model routing → parallel agent dispatch → join → output',
      agent: 'atlas',
      nodes: (() => {
        const input = makeNode('Data.Input', 'User Query', 0, 150);
        const route = makeNode('Route.Switch', 'Atlas Route', 250, 150);
        const parallel = makeNode('Route.Parallel', 'Agent Dispatch', 500, 150);
        const join = makeNode('Route.Join', 'Synthesis', 750, 150);
        const output = makeNode('Data.Output', 'Response', 1000, 150);
        return [input, route, parallel, join, output];
      })(),
      edges: [], // Wired at instantiation based on node IDs
      safeConfig: { required: ['Flow graph acyclicity'], forbidden: ['Self-referential routing'], constraints: ['Max 3 parallel branches'] },
      tags: ['routing', 'orchestration', 'multi-agent'],
    },

    // ── Aegis: Secured Pipeline ──
    {
      id: 'aegis-secured',
      name: 'Aegis Secured Pipeline',
      description: 'Input → PII guard → injection guard → policy gate → output',
      agent: 'aegis',
      nodes: (() => {
        const input = makeNode('Data.Input', 'Untrusted Input', 0, 150);
        const pii = makeNode('Guard.PII', 'PII Scan', 250, 150);
        const inject = makeNode('Guard.Injection', 'Injection Check', 500, 150);
        const gate = makeNode('Policy.Gate', 'Policy Gate', 750, 150);
        const output = makeNode('Data.Output', 'Secured Output', 1000, 150);
        return [input, pii, inject, gate, output];
      })(),
      edges: [],
      safeConfig: { required: ['Guard at every I/O crossing', 'PII redaction'], forbidden: ['Unguarded external calls', 'Policy bypass'], constraints: ['Guard latency < 5ms'] },
      tags: ['security', 'guards', 'policy'],
    },

    // ── Sparky: Tool Execution Pipeline ──
    {
      id: 'sparky-tool-pipeline',
      name: 'Sparky Tool Pipeline',
      description: 'Input → tool resolution → execution → trace → output',
      agent: 'sparky',
      nodes: (() => {
        const input = makeNode('Data.Input', 'Tool Request', 0, 150);
        const resolve = makeNode('Tool.Execute', 'Tool Resolve', 250, 150);
        const trace = makeNode('Trace.Emit', 'Execution Trace', 500, 150);
        const output = makeNode('Data.Output', 'Tool Result', 750, 150);
        return [input, resolve, trace, output];
      })(),
      edges: [],
      safeConfig: { required: ['Tool bindings resolved', 'Execution traced'], forbidden: ['Hardcoded secrets'], constraints: ['Tool timeout ≤ 30s'] },
      tags: ['tools', 'execution', 'engineering'],
    },

    // ── Echo: Observability Pipeline ──
    {
      id: 'echo-observability',
      name: 'Echo Observability',
      description: 'Input → span → metric → audit → alert (conditional)',
      agent: 'echo',
      nodes: (() => {
        const input = makeNode('Data.Input', 'Event Stream', 0, 150);
        const span = makeNode('Trace.Span', 'Trace Span', 250, 150);
        const metric = makeNode('Monitor.Metric', 'Metric Emit', 500, 100);
        const audit = makeNode('Audit.Commit', 'Audit Record', 500, 250);
        const alert = makeNode('Monitor.Alert', 'Anomaly Alert', 750, 150);
        return [input, span, metric, audit, alert];
      })(),
      edges: [],
      safeConfig: { required: ['Continuous trace emission', 'Baseline drift detection'], forbidden: ['Silent failures', 'Trace tampering'], constraints: ['Trace latency ≤ 2ms'] },
      tags: ['observability', 'traces', 'monitoring'],
    },

    // ── Themis: Governance Pipeline ──
    {
      id: 'themis-governance',
      name: 'Themis Governance',
      description: 'Input → policy check → attestation → audit commit → output',
      agent: 'themis',
      nodes: (() => {
        const input = makeNode('Data.Input', 'Governance Request', 0, 150);
        const policy = makeNode('Policy.Check', 'Policy Evaluate', 250, 150);
        const attest = makeNode('Trust.Attest', 'Attestation', 500, 150);
        const audit = makeNode('Audit.Commit', 'Ledger Commit', 750, 150);
        const output = makeNode('Data.Output', 'Attested Output', 1000, 150);
        return [input, policy, attest, audit, output];
      })(),
      edges: [],
      safeConfig: { required: ['Dual-agent signature', 'Attestation ledger entry'], forbidden: ['Single-agent attestation', 'Unsigned policy changes'], constraints: ['Signature: Ed25519'] },
      tags: ['governance', 'compliance', 'attestation'],
    },

    // ── Zero Trust: Hardened Pipeline (Reference Implementation) ──
    {
      id: 'zt-hardened-pipeline',
      name: 'ZT Hardened Pipeline',
      description: 'Full Zero Trust: Auth → Vault → Segment → Guard → Tool → Audit → KillSwitch → Output',
      agent: 'aegis',
      nodes: (() => {
        const input = makeNode('Data.Input', 'Untrusted Request', 0, 150);
        const auth = makeNode('Auth.Verify', 'Verify Identity', 200, 150);
        const vault = makeNode('Vault.Lease', 'Credential Lease', 400, 150);
        const segment = makeNode('Segment.Boundary', 'Isolation Boundary', 600, 150);
        const guard = makeNode('Guard.Injection', 'Injection Defense', 800, 150);
        const tool = makeNode('Tool.HTTP', 'Secured API Call', 1000, 150);
        const audit = makeNode('Audit.Commit', 'Immutable Log', 1200, 150);
        const kill = makeNode('Control.KillSwitch', 'Emergency Halt', 1200, 300);
        const output = makeNode('Data.Output', 'Verified Output', 1400, 150);
        return [input, auth, vault, segment, guard, tool, audit, kill, output];
      })(),
      edges: [],
      safeConfig: {
        required: ['Identity verification at entry', 'Dynamic credentials via vault', 'Micro-segmentation', 'Injection defense', 'Immutable audit log', 'Kill switch capability'],
        forbidden: ['Static credentials', 'Unguarded external calls', 'Missing audit trail', 'Bypassed policy gates'],
        constraints: ['Credential TTL ≤ 300s', 'All data encrypted in transit', 'Kill switch latency < 100ms'],
      },
      tags: ['zero-trust', 'hardened', 'reference-implementation', 'vault', 'segmentation'],
    },

    // ── Vault-Secured Credential Flow ──
    {
      id: 'vault-credential-flow',
      name: 'Vault Credential Flow',
      description: 'Dynamic credential lifecycle: Fetch → Lease → Use → Audit → Revoke',
      agent: 'aegis',
      nodes: (() => {
        const input = makeNode('Data.Input', 'Credential Request', 0, 150);
        const fetch = makeNode('Vault.Fetch', 'Fetch Secret', 200, 150);
        const lease = makeNode('Vault.Lease', 'Acquire Lease', 400, 150);
        const use = makeNode('Tool.HTTP', 'Use Credential', 600, 150);
        const audit = makeNode('Audit.Commit', 'Log Access', 800, 150);
        const revoke = makeNode('Vault.Revoke', 'Revoke Lease', 1000, 150);
        const output = makeNode('Data.Output', 'Result', 1200, 150);
        return [input, fetch, lease, use, audit, revoke, output];
      })(),
      edges: [],
      safeConfig: {
        required: ['Vault-backed credentials only', 'Time-bound leases', 'Access audited'],
        forbidden: ['Static API keys', 'Credentials in config', 'Unrevoked leases'],
        constraints: ['Lease TTL ≤ 300s', 'Rotation policy: strict (30-day)'],
      },
      tags: ['vault', 'credentials', 'dynamic', 'zero-trust'],
    },

    // ── Canary Deployment Pipeline ──
    {
      id: 'canary-deployment',
      name: 'Canary Deployment',
      description: 'Safe rollout: Input → Canary Gate → [canary|stable] → Monitor → Circuit Breaker → Output',
      agent: 'echo',
      nodes: (() => {
        const input = makeNode('Data.Input', 'Request', 0, 200);
        const canary = makeNode('Control.Canary', 'Canary Gate', 250, 200);
        const canaryPath = makeNode('Model.Invoke', 'New Version', 500, 100);
        const stablePath = makeNode('Model.Invoke', 'Stable Version', 500, 300);
        const monitor = makeNode('Monitor.Metric', 'Health Metrics', 750, 200);
        const breaker = makeNode('Control.CircuitBreaker', 'Circuit Breaker', 1000, 200);
        const output = makeNode('Data.Output', 'Response', 1250, 200);
        return [input, canary, canaryPath, stablePath, monitor, breaker, output];
      })(),
      edges: [],
      safeConfig: {
        required: ['Canary percentage ≤ 5%', 'Automatic rollback on failure', 'Health monitoring'],
        forbidden: ['Full deployment without canary', 'Disabled circuit breaker'],
        constraints: ['Promote threshold ≥ 99%', 'Rollback latency < 1s'],
      },
      tags: ['canary', 'deployment', 'circuit-breaker', 'zero-trust'],
    },
  ];
}

/**
 * Wire a template's edges based on sequential node order.
 * For templates with linear flow, connects each node's first output
 * to the next node's first input.
 */
export function wireTemplateEdges(template: AgentFlowTemplate): ZPFlowEdge[] {
  const edges: ZPFlowEdge[] = [];
  for (let i = 0; i < template.nodes.length - 1; i++) {
    const source = template.nodes[i];
    const target = template.nodes[i + 1];
    if (!source.ports.length || !target.ports.length) continue; // Skip nodes with no ports
    const sourcePort = source.ports.find(p => p.type === 'output') || source.ports[source.ports.length - 1];
    const targetPort = target.ports.find(p => p.type === 'input') || target.ports[0];
    if (!sourcePort || !targetPort) continue; // Guard against undefined ports
    edges.push({
      id: edgeId(),
      source: source.id,
      sourcePort: sourcePort.id,
      target: target.id,
      targetPort: targetPort.id,
    });
  }
  return edges;
}
