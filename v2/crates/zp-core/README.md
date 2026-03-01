# zp-core

Shared types, traits, and error definitions for the ZeroPoint v2 workspace.

This crate is the vocabulary of the system. Every other ZeroPoint crate depends on it. It defines the data structures that flow through the governance pipeline — requests, responses, policy decisions, capability grants, audit entries, governance events, and the error types that unify error handling across the workspace.

## Modules

### types.rs — Core Conversation Types

The fundamental request/response flow: `Request`, `Response`, `ConversationId`, `MessageId`, `Channel` (Cli, Api, Slack, Discord, WebDashboard), `ToolCall`, `ToolResult`, `OperatorIdentity`, and `SessionContext`. Also re-exports receipt types from `zp-receipt`: `Receipt`, `PortableReceipt`, `Status`, `TrustGrade`, `ReceiptChain`, and `Signer`.

### error.rs — Unified Error Type

`ZpError` covers every failure mode in the system: policy blocks, credential denials, provider errors, WASM fuel exhaustion, audit chain breaks, signature failures, database errors, and more. Conversion impls from `rusqlite::Error` and `serde_json::Error` are provided.

### policy.rs — Policy Vocabulary

The graduated severity model. `TrustTier` defines three levels of cryptographic identity (Tier0 unsigned, Tier1 self-signed, Tier2 chain-signed). `PolicyDecision` has five outcomes ordered by severity: Allow, Warn, Review, Sanitize, Block — the most restrictive always wins. `PolicyContext` carries the action type, trust tier, channel, and optional `MeshPeerContext` for reputation-gated mesh decisions. `RiskLevel` (Low, Medium, High, Critical) drives model routing. `MeshAction` enumerates the six mesh operations subject to reputation gating.

### capability_grant.rs — Signed Capability Tokens

`CapabilityGrant` is a signed, portable authorization token. It specifies what capability is granted (`GrantedCapability`: Read, Write, Execute, CredentialAccess, ApiCall, ConfigChange, MeshSend, or Custom), what constraints apply (`Constraint`: MaxCost, RateLimit, ScopeRestriction, TimeWindow, RequireReceipt, RequireEscalation), who granted it, who received it, and when it expires. Grants support a builder pattern, Ed25519 signing and verification, glob-based scope matching, and delegation to sub-agents with depth and scope checks.

### delegation_chain.rs — Chain Verification

`DelegationChain` validates an ordered list of capability grants from root to leaf. Eight invariants are enforced: root has no parent and depth 0, parent-child linkage via grant IDs, monotonically increasing depth, child scope is a subset of parent scope, grantor matches parent's grantee, chain doesn't exceed max delegation depth, no child outlives parent, and all signatures verify if present.

### governance.rs — Governance Events

`GovernanceEvent` is an immutable record of every governance decision point. Over 30 event types cover the full lifecycle: guard evaluation, policy evaluation, capability grants and delegations, policy advertisement and agreement, delegation chain verification, audit challenges and attestations, reputation computation and broadcasting, receipt forwarding and receiving, and reputation gating. Each event has a Blake3 hash for deterministic identification.

### audit.rs — Audit Trail Types

`AuditEntry` is a single link in the hash-chained audit trail. Fields include actor, action, policy decision, receipt reference, and a cryptographic hash chaining to the previous entry. `AuditAction` covers every recordable action: messages received, responses generated, tools invoked, credentials injected, policies evaluated, outputs sanitized, and skills activated.

### capability.rs — Runtime Capabilities

`Capability` defines what tools are available for a specific request, as determined by the policy engine. `PipelineResult` represents the outcome of pipeline preparation: Ready (with capabilities), Denied, or NeedsInteraction. `ModelPreference` routes requests to appropriate LLM classes (Any, Strong, RequireStrong, LocalOnly, Specific).

### skill.rs — Skill Definitions

`SkillManifest` declares a skill's name, description, tools, keywords, and prompt template. `SkillOrigin` tracks provenance (BuiltIn, Extracted, Community, Enterprise). `SkillCandidate` represents a proposed skill from the learning loop, with approval status tracking.

### episode.rs — Learning Loop Episodes

`Episode` records one complete interaction cycle — the potential input to skill extraction. Includes request category, tools used, model, outcome (Success, Failure, Partial), user feedback, and duration.

### provider.rs — LLM Provider Types

`ProviderCapabilities` (is_local, max_context, supports_tools, strength) and `ProviderHealth` (Healthy, Degraded, Unavailable) for the LLM routing layer.

## Design Patterns

All types derive `Serialize` and `Deserialize` for cross-boundary portability. Time-based UUIDs (`Uuid::now_v7()`) provide natural ordering. Ed25519 signatures protect capability grants and audit entries. Blake3 hashes ensure chain integrity. Builder patterns provide ergonomic construction for complex types like `CapabilityGrant` and `ConstraintContext`.
