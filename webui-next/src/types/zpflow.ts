/**
 * ZPFlow Types — ZeroPoint Flow Specification
 *
 * Defines the typed flow graph that maps Node-RED concepts onto ZeroPoint's
 * trust-centric execution model. Agents provide pre-built flow templates;
 * Surfaces become flow execution contexts.
 *
 * Architecture:
 *   Authoring (MapStation canvas) → Compile (zpflow spec) →
 *   Execution (sandboxed runner) → Evidence (attestation ledger) →
 *   Policy (capability decisions)
 */

import type { AgentId } from '../components/Bridge/types';
import type { SurfaceTrustTier } from './surface';

// =============================================================================
// ZP ENVELOPE — Signed message wrapper for all flow operations
// =============================================================================

export interface ZPEnvelope {
  /** Unique execution trace identifier */
  trace_id: string;
  /** Agent identity that produced this envelope */
  actor: AgentId | string;
  /** SHA-256 hash of the compiled flow graph */
  flow_hash: string;
  /** Ed25519 signature over flow_hash (present after securing phase) */
  flow_sig?: string;
  /** Active policy gate configuration */
  policy?: ZPPolicyConfig;
  /** Declared capability set */
  capabilities: string[];
  /** Integrity hash chain (present after canonicalization) */
  integrity?: ZPIntegrityChain;
  /** Origin and attestation chain (present after canonicalization) */
  provenance?: ZPProvenance;
  /** ISO timestamp */
  timestamp: string;
}

export interface ZPPolicyConfig {
  /** Policy gates that must pass before execution */
  gates: string[];
  /** Maximum trust tier this flow may reach */
  maxTrustTier: SurfaceTrustTier;
  /** Whether human approval is required */
  requiresHumanApproval: boolean;
}

export interface ZPIntegrityChain {
  /** Ordered list of hashes forming the integrity chain */
  hashes: string[];
  /** Algorithm used (default: sha256) */
  algorithm: string;
}

export interface ZPProvenance {
  /** Agent who created the attestation */
  attestedBy: AgentId;
  /** Counter-signing agent (if dual-signature) */
  counterSignedBy?: AgentId;
  /** Attestation timestamp */
  attestedAt: string;
  /** Ledger entry reference */
  ledgerRef?: string;
}

// =============================================================================
// NODE TAXONOMY — Three categories matching Node-RED synthesis
// =============================================================================

/**
 * Core Execution nodes — data transformation and tool invocation
 */
export type CoreExecutionNodeType =
  | 'Model.Invoke'       // LLM call
  | 'Tool.HTTP'          // External API call
  | 'Tool.Execute'       // Local tool execution
  | 'Transform.Map'      // Data transformation
  | 'Transform.Filter'   // Data filtering
  | 'Transform.Reduce'   // Data aggregation
  | 'Route.Switch'       // Conditional branching
  | 'Route.Parallel'     // Fan-out parallel execution
  | 'Route.Join'         // Fan-in merge
  | 'Data.Input'         // Flow input
  | 'Data.Output';       // Flow output

/**
 * Trust & Safety nodes — security enforcement and policy
 */
export type TrustSafetyNodeType =
  | 'Guard.PII'          // PII detection and redaction
  | 'Guard.Injection'    // Prompt injection defense
  | 'Guard.Content'      // Content safety filter
  | 'Policy.Check'       // Policy evaluation (non-blocking)
  | 'Policy.Gate'        // Policy enforcement (blocking)
  | 'Trust.Boundary'     // Trust tier transition point
  | 'Trust.Attest'       // Generate attestation
  | 'Auth.Verify';       // Capability/identity verification

/**
 * Evidence & Observability nodes — audit trail and monitoring
 */
export type EvidenceNodeType =
  | 'Trace.Emit'         // Emit structured trace event
  | 'Trace.Span'         // Create trace span (start/end)
  | 'Artifact.Store'     // Store artifact with integrity hash
  | 'Audit.Commit'       // Commit audit record to ledger
  | 'Monitor.Metric'     // Emit metric observation
  | 'Monitor.Alert';     // Trigger alert condition

/**
 * Control nodes — Human-in-the-loop, kill switch, throttle, canary (ZT §1.9)
 */
export type ControlNodeType =
  | 'Control.KillSwitch'    // Halt flow execution immediately (ZT §1.9.1)
  | 'Control.Throttle'      // Rate-limit activity (ZT §1.9.2)
  | 'Control.HumanApproval' // Block until human approves (ZT §1.9.1)
  | 'Control.Canary'        // Canary deployment gate (ZT §1.9.3)
  | 'Control.CircuitBreaker'; // Open circuit on failure threshold

/**
 * Vault & Credential nodes — Dynamic credential management (ZT §1.1.4, §1.1.5)
 */
export type VaultNodeType =
  | 'Vault.Fetch'           // Fetch dynamic credential from encrypted store
  | 'Vault.Rotate'          // Trigger credential rotation
  | 'Vault.Lease'           // Acquire time-bound credential lease
  | 'Vault.Revoke';         // Revoke credential immediately

/**
 * Segmentation nodes — Micro-segmentation and isolation (ZT §1.2.1)
 */
export type SegmentationNodeType =
  | 'Segment.Boundary'      // Micro-segment isolation boundary
  | 'Segment.Encrypt';      // Encrypt data crossing segment boundary (ZT §1.4.1)

/** Union of all flow node types */
export type ZPFlowNodeType =
  | CoreExecutionNodeType
  | TrustSafetyNodeType
  | EvidenceNodeType
  | ControlNodeType
  | VaultNodeType
  | SegmentationNodeType;

/** Category classification for palette grouping */
export type ZPNodeCategory = 'core' | 'trust' | 'evidence' | 'control' | 'vault' | 'segment';

export function getNodeCategory(nodeType: ZPFlowNodeType): ZPNodeCategory {
  if (nodeType.startsWith('Model.') || nodeType.startsWith('Tool.') ||
      nodeType.startsWith('Transform.') || nodeType.startsWith('Route.') ||
      nodeType.startsWith('Data.')) return 'core';
  if (nodeType.startsWith('Guard.') || nodeType.startsWith('Policy.') ||
      nodeType.startsWith('Trust.') || nodeType.startsWith('Auth.')) return 'trust';
  if (nodeType.startsWith('Control.')) return 'control';
  if (nodeType.startsWith('Vault.')) return 'vault';
  if (nodeType.startsWith('Segment.')) return 'segment';
  return 'evidence';
}

// =============================================================================
// FLOW GRAPH — The authored/compiled flow definition
// =============================================================================

/** Port on a flow node (input or output) */
export interface ZPFlowPort {
  id: string;
  label: string;
  type: 'input' | 'output';
  /** Data schema hint (e.g., 'string', 'json', 'stream') */
  dataType?: string;
}

/** A single node in the flow graph */
export interface ZPFlowNode {
  /** Unique node ID within this flow */
  id: string;
  /** Node type from taxonomy */
  type: ZPFlowNodeType;
  /** Human-readable label */
  label: string;
  /** Canvas position */
  position: { x: number; y: number };
  /** Typed configuration for this node type */
  config: Record<string, unknown>;
  /** Input/output ports */
  ports: ZPFlowPort[];
  /** Which agent template this node originated from (if any) */
  agentOrigin?: AgentId;
  /** Trust tier required to execute this node */
  requiredTrustTier?: SurfaceTrustTier;
}

/** An edge connecting two ports in the flow graph */
export interface ZPFlowEdge {
  id: string;
  /** Source node ID */
  source: string;
  /** Source port ID */
  sourcePort: string;
  /** Target node ID */
  target: string;
  /** Target port ID */
  targetPort: string;
  /** Edge metadata (e.g., condition for switch branches) */
  condition?: string;
  /** Visual label */
  label?: string;
}

/** Safe configuration constraints for a flow */
export interface ZPSafeConfig {
  required: string[];
  forbidden: string[];
  constraints: string[];
}

/**
 * Lifecycle phase tracking — maps to the 5 surface lifecycle phases
 */
export type ZPFlowPhase =
  | 'draft'              // Being authored in canvas
  | 'installed'          // Manifest registered (Tier D)
  | 'adapted'            // Tool bindings resolved (Tier C)
  | 'secured'            // Trust boundaries applied (Tier B)
  | 'canonicalized'      // Attested and frozen (Tier A)
  | 'operational';       // Live execution (Attested)

/**
 * The complete ZPFlow specification — output of the compile step
 */
export interface ZPFlowSpec {
  /** Flow identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** Description */
  description: string;
  /** Semantic version */
  version: string;
  /** Current lifecycle phase */
  phase: ZPFlowPhase;
  /** All nodes in this flow */
  nodes: ZPFlowNode[];
  /** All edges connecting nodes */
  edges: ZPFlowEdge[];
  /** Safe configuration constraints */
  safeConfig: ZPSafeConfig;
  /** Surface this flow is bound to */
  surfaceId?: string;
  /** Envelope (populated during compile/sign) */
  envelope?: ZPEnvelope;
  /** Agent template this flow was derived from */
  templateAgent?: AgentId;
  /** Creation timestamp */
  createdAt: string;
  /** Last modification timestamp */
  updatedAt: string;
}

// =============================================================================
// AGENT FLOW TEMPLATES — Pre-built patterns derived from agent expertise
// =============================================================================

/** Metadata for a node type in the palette */
export interface ZPNodeTemplate {
  type: ZPFlowNodeType;
  label: string;
  description: string;
  category: ZPNodeCategory;
  /** Default ports for this node type */
  defaultPorts: ZPFlowPort[];
  /** Default configuration */
  defaultConfig: Record<string, unknown>;
  /** Which agent typically uses this node */
  agentAffinity?: AgentId;
  /** Icon for palette display */
  icon: string;
  /** Color for visual distinction */
  color: string;
}

/** An agent's pre-built flow template */
export interface AgentFlowTemplate {
  id: string;
  name: string;
  description: string;
  agent: AgentId;
  /** Pre-wired nodes */
  nodes: ZPFlowNode[];
  /** Pre-wired edges */
  edges: ZPFlowEdge[];
  /** Safe config the template enforces */
  safeConfig: ZPSafeConfig;
  /** Tags for searchability */
  tags: string[];
}

// =============================================================================
// COMPILE / SIGN PIPELINE
// =============================================================================

/** Request to compile a draft flow into a signed spec */
export interface ZPCompileRequest {
  /** The flow graph to compile */
  nodes: ZPFlowNode[];
  edges: ZPFlowEdge[];
  /** Flow metadata */
  name: string;
  description: string;
  /** Target surface */
  surfaceId?: string;
  /** Agent requesting compilation */
  requestedBy: AgentId;
}

/** Response from the compile/sign pipeline */
export interface ZPCompileResponse {
  success: boolean;
  /** Compiled flow spec (if successful) */
  spec?: ZPFlowSpec;
  /** Validation errors */
  errors?: ZPValidationError[];
  /** Warnings (non-blocking) */
  warnings?: string[];
  /** Zero Trust compliance assessment */
  ztCompliance?: ZTComplianceReport;
  /** Blast radius analysis */
  blastRadius?: ZPBlastRadiusReport;
}

export interface ZPValidationError {
  nodeId?: string;
  edgeId?: string;
  code: string;
  message: string;
  severity: 'error' | 'warning';
}

// =============================================================================
// ZERO TRUST COMPLIANCE — Reference Implementation (ZT §1–§5)
// =============================================================================

/** Zero Trust compliance assessment result */
export interface ZTComplianceReport {
  /** Overall compliance score 0–100 */
  score: number;
  /** Compliance tier: 'non-compliant' | 'partial' | 'compliant' | 'hardened' */
  tier: ZTComplianceTier;
  /** Per-pillar assessment */
  pillars: ZTPillarAssessment[];
  /** Critical gaps that must be addressed */
  criticalGaps: ZTComplianceGap[];
  /** Recommendations ordered by priority */
  recommendations: string[];
  /** Timestamp of assessment */
  assessedAt: string;
}

export type ZTComplianceTier = 'non-compliant' | 'partial' | 'compliant' | 'hardened';

/** Assessment of a single Zero Trust pillar */
export interface ZTPillarAssessment {
  /** Pillar identifier matching the ZT document sections */
  pillar: ZTPillar;
  /** Pillar display name */
  name: string;
  /** Whether this pillar is satisfied */
  satisfied: boolean;
  /** Nodes that contribute to this pillar */
  coveringNodes: string[];
  /** What's missing (if not satisfied) */
  gap?: string;
}

export type ZTPillar =
  | 'iam'                 // §1.1 Identity and Access Management
  | 'network'             // §1.2 Network Security (micro-segmentation)
  | 'endpoint'            // §1.3 Endpoint Security
  | 'data'                // §1.4 Data Security
  | 'application'         // §1.5 Application Security
  | 'tool-registry'       // §1.6 Tool Security
  | 'inspection'          // §1.7 Inspection and Enforcement (AI firewall)
  | 'traceability'        // §1.8 Traceability and Monitoring
  | 'human-in-loop';      // §1.9 Human in the Loop

/** A specific compliance gap */
export interface ZTComplianceGap {
  pillar: ZTPillar;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  /** Suggested node type to add */
  suggestedNode?: ZPFlowNodeType;
}

// =============================================================================
// BLAST RADIUS ANALYSIS — Assume Breach (ZT §5.2)
// =============================================================================

/** Blast radius analysis for a compromised node */
export interface ZPBlastRadius {
  /** The node being analyzed as compromised */
  compromisedNodeId: string;
  /** Direct downstream nodes affected */
  directImpact: string[];
  /** Transitive closure of all reachable nodes */
  transitiveImpact: string[];
  /** Trust boundaries crossed */
  boundariesCrossed: string[];
  /** Capabilities exposed if this node is compromised */
  exposedCapabilities: string[];
  /** Risk score 0–100 (higher = more damage) */
  riskScore: number;
  /** Whether blast radius is contained by trust boundaries */
  contained: boolean;
}

/** Full blast radius report for the entire flow */
export interface ZPBlastRadiusReport {
  /** Per-node blast radius analysis */
  nodeAnalysis: ZPBlastRadius[];
  /** Maximum blast radius across all nodes */
  maxBlastRadius: number;
  /** Nodes with highest risk scores (top 3) */
  criticalNodes: string[];
  /** Overall containment assessment */
  containmentScore: number;
}

// =============================================================================
// VAULT INTEGRATION — Dynamic Credentials (ZT §1.1.4, §1.1.5)
// =============================================================================

/** Credential lease — time-bound access (ZT §5.3.3) */
export interface ZPCredentialLease {
  /** Lease identifier */
  leaseId: string;
  /** Secret key in the vault */
  secretKey: string;
  /** Provider (anthropic, openai, etc.) */
  provider?: string;
  /** Lease granted at */
  grantedAt: string;
  /** Lease expires at */
  expiresAt: string;
  /** Maximum TTL in seconds */
  ttlSeconds: number;
  /** Whether lease has been revoked */
  revoked: boolean;
  /** Which flow spec requested this lease */
  flowSpecId: string;
  /** Which node in the flow holds this lease */
  nodeId: string;
}

/** Vault operation request from a flow node */
export interface ZPVaultRequest {
  /** Operation type */
  operation: 'fetch' | 'rotate' | 'lease' | 'revoke';
  /** Secret key */
  secretKey: string;
  /** Requesting flow's envelope (for authorization) */
  envelope: ZPEnvelope;
  /** Lease TTL (for lease operations) */
  leaseTtlSeconds?: number;
  /** Lease ID (for revoke operations) */
  leaseId?: string;
}

/** Vault operation response */
export interface ZPVaultResponse {
  success: boolean;
  /** Lease info (for fetch/lease ops) */
  lease?: ZPCredentialLease;
  /** Error message */
  error?: string;
  /** Audit trail entry ID */
  auditRef?: string;
}

// =============================================================================
// FLOW STATE MACHINE — Runtime control (ZT §1.9)
// =============================================================================

/** Runtime state of a deployed flow */
export type ZPFlowRuntimeState =
  | 'idle'          // Deployed but not executing
  | 'running'       // Currently executing
  | 'paused'        // Paused by human or throttle
  | 'halted'        // Kill switch activated
  | 'completed'     // Finished execution
  | 'failed'        // Failed with error
  | 'canary';       // Running in canary mode (limited blast radius)

/** Flow runtime control command */
export interface ZPFlowControlCommand {
  /** Command type */
  command: 'start' | 'pause' | 'resume' | 'halt' | 'canary_promote' | 'canary_rollback';
  /** Target flow spec ID */
  flowSpecId: string;
  /** Issuing agent */
  issuedBy: AgentId | string;
  /** Reason for the command */
  reason: string;
  /** Timestamp */
  issuedAt: string;
}

/** Flow runtime status */
export interface ZPFlowRuntimeStatus {
  /** Flow spec ID */
  flowSpecId: string;
  /** Current runtime state */
  state: ZPFlowRuntimeState;
  /** Active credential leases */
  activeLeases: ZPCredentialLease[];
  /** Recent control commands */
  controlHistory: ZPFlowControlCommand[];
  /** Current canary percentage (0–100, only in canary state) */
  canaryPercentage?: number;
  /** Health metrics */
  health: {
    errorRate: number;
    avgLatencyMs: number;
    activeExecutions: number;
    throttledCount: number;
  };
}
