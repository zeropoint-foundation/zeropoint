# Verb-Set Inventory — May 2026

*Phase 1 input to `proto/v1/*.proto` drafting. Not a design doc; tables-heavy, prose minimal.*

*Conventions: verb-first with resource (`EvaluateGate`). Response suffix: `*Envelope` = plain, `Signed*` = signed, `*Receipt` = full chained. `stream T` = server-streaming. Source column cites HTTP route(s) or mesh `EnvelopeType` variant.*

---

## 1. Guard

| Verb | Description | Request | Response | Streaming? | Subsumes |
|---|---|---|---|---|---|
| `EvaluateGate` | Evaluate a tool/action against active policy; returns allow/deny/escalate verdict | `EvaluateGateRequest` | `GuardReceipt` | no | `POST /api/v1/evaluate`, `POST /api/v1/guard/evaluate`, `POST /api/v1/gate/tool-call`, mesh `EnvelopeType::GuardRequest` → `GuardResponse` |
| `ProxyCall` | Governance-aware LLM provider proxy; applies policy, meters tokens, issues receipt | `ProxyCallRequest` | `ProxyReceipt` | no | `POST /api/v1/proxy/*proxy_path` |
| `LoadPolicyModule` | Load a WASM policy module into the runtime | `LoadPolicyModuleRequest` | `PolicyModuleReceipt` | no | `POST /api/v1/policy/wasm/load` |
| `DisablePolicyModule` | Disable a loaded WASM module by hash | `DisablePolicyModuleRequest` | `PolicyModuleReceipt` | no | `POST /api/v1/policy/wasm/:hash/disable` |
| `EnablePolicyModule` | Re-enable a disabled WASM module by hash | `EnablePolicyModuleRequest` | `PolicyModuleReceipt` | no | `POST /api/v1/policy/wasm/:hash/enable` |
| `ListPolicyModules` | List all loaded WASM policy modules | `ListPolicyModulesRequest` | `PolicyModulesEnvelope` | no | `GET /api/v1/policy/wasm` |
| `GetPolicyRules` | Return the active policy ruleset | `GetPolicyRulesRequest` | `SignedPolicyRules` | no | `GET /api/v1/policy/rules` |
| `AdvancePolicyVersion` | Bump monotonic policy version (downgrade resistance) | `AdvancePolicyVersionRequest` | `PolicyVersionReceipt` | no | `POST /api/v1/security/policy-version/advance` |
| `GetPolicyVersion` | Return the current policy version counter | `GetPolicyVersionRequest` | `SignedPolicyVersion` | no | `GET /api/v1/security/policy-version` |

**Notes:**
- `EvaluateGate` subsumes three HTTP duplicates plus the mesh guard request/response pair. The mesh `GuardRequest`/`GuardResponse` envelope types become the same verb — the response category is a `GuardReceipt` in all transports.
- `ProxyCall` is receipt-native by design (the existing `proxy.rs` already generates receipts); it is a verb, not dashboard glue.
- Policy module management verbs (`LoadPolicyModule`, `Disable/Enable`) are gate-configuration operations, naturally Guard-service.

---

## 2. Delegation

| Verb | Description | Request | Response | Streaming? | Subsumes |
|---|---|---|---|---|---|
| `GrantCapability` | Issue a new top-level capability grant | `GrantCapabilityRequest` | `DelegationReceipt` | no | `POST /api/v1/capabilities/grant` |
| `DelegateCapability` | Delegate an existing capability to another agent | `DelegateCapabilityRequest` | `DelegationReceipt` | no | `POST /api/v1/capabilities/delegate`, mesh `EnvelopeType::Delegation` |
| `VerifyDelegationChain` | Verify the integrity of a delegation chain | `VerifyDelegationChainRequest` | `SignedDelegationChainVerification` | no | `POST /api/v1/capabilities/verify-chain` |
| `RenewLease` | Renew a standing delegation lease | `RenewLeaseRequest` | `DelegationReceipt` | no | `POST /api/v1/lease/renew` |
| `WithdrawCapability` | Revoke a previously granted capability | `WithdrawCapabilityRequest` | `WithdrawalReceipt` | no | *(no current HTTP route — capability gap, see open questions)* |
| `GetCredentials` | Retrieve credentials for a provider | `GetCredentialsRequest` | `SignedCredentialsEnvelope` | no | `GET /api/v1/credentials/:provider` |

**Notes:**
- `VerifyDelegationChain` is a read that drives downstream delegation decisions — a `SignedDelegationChainVerification` (signed envelope, not chained) is appropriate. See open questions for the cross-service tension.
- `WithdrawCapability` has no current HTTP route. It corresponds to V.3 (delegation withdrawal) in the architecture doc — flagged as an open dimension. The verb slot is reserved; the implementation is pending the withdrawal mechanics decision.
- `GetCredentials` is Delegation-service work because credentials are capability-adjacent (they authorize what a capability can do). Could argue NodeStatus, but the access-control framing wins.

---

## 3. Receipts

| Verb | Description | Request | Response | Streaming? | Subsumes |
|---|---|---|---|---|---|
| `GenerateReceipt` | Issue a new signed, chained receipt for an action | `GenerateReceiptRequest` | `Receipt` | no | `POST /api/v1/receipts/generate`, `POST /api/v1/receipts` (external) |
| `IssueAttestation` | Issue a signed attestation (course completion, external fact) | `IssueAttestationRequest` | `AttestationReceipt` | no | `POST /api/v1/attestations` |
| `LookupAttestation` | Look up a single attestation by ID | `LookupAttestationRequest` | `SignedAttestationEnvelope` | no | `GET /api/v1/attestations` |
| `ListAttestations` | List all attestations | `ListAttestationsRequest` | `AttestationsEnvelope` | no | `GET /api/v1/attestations/all` |
| `WatchReceipts` | Stream receipts matching a filter as they are issued | `WatchReceiptsRequest` | `stream Receipt` | yes | `GET /api/v1/events/stream` (SSE, filtered to receipt events) |
| `ReceiptForToolCall` | Issue a receipt for a governed tool operation | `ReceiptForToolCallRequest` | `Receipt` | no | `POST /api/v1/tools/receipt` |

**Notes:**
- `GenerateReceipt` and `ReceiptForToolCall` may collapse into one verb; split kept here because the tool-call path carries tool-specific context. Decision call for Phase 3.
- `IssueAttestation` / `LookupAttestation` / `ListAttestations` currently live in `attestations.rs` framed around course completions. The receipt-native design already exists (`attestations.rs` signs and hash-chains). These are receipts of external facts; they belong in the Receipts service, not a bespoke attestations service.
- `WatchReceipts` subsumes the SSE event stream for receipt events specifically. The SSE infrastructure path stays (see "stays as infrastructure" below).

---

## 4. Audit

| Verb | Description | Request | Response | Streaming? | Subsumes |
|---|---|---|---|---|---|
| `GetChainHead` | Return the current audit chain head (latest entry hash + signature) | `GetChainHeadRequest` | `SignedChainHead` | no | `GET /api/v1/audit/chain-head` |
| `QueryAuditEntries` | Return a filtered page of audit entries | `QueryAuditEntriesRequest` | `SignedAuditEntriesEnvelope` | no | `GET /api/v1/audit/entries` |
| `VerifyChainIntegrity` | Attest that the local audit chain is internally consistent | `VerifyChainIntegrityRequest` | `AttestationReceipt` | no | `GET /api/v1/audit/verify` |
| `TailAuditEntries` | Stream new audit entries as they are appended | `TailAuditEntriesRequest` | `stream AuditEntry` | yes | `GET /api/v1/events/stream` (SSE, filtered to audit events) |
| `ReconstituteTrustState` | Rebuild trust state from the audit chain | `ReconstituteTrustStateRequest` | `ReconstitutionReceipt` | no | `POST /api/v1/security/reconstitute` |
| `AnchorChainHead` | Trigger OpenTimestamps anchoring of the current chain head | `AnchorChainHeadRequest` | `AnchoringReceipt` | no | *(no current HTTP route; anchor_pipeline.rs exists but is internal)* |
| `GetSystemState` | Return derived system state from the receipt chain | `GetSystemStateRequest` | `SignedSystemStateEnvelope` | no | `GET /api/v1/system/state` |

**Notes:**
- `GetChainHead` and `QueryAuditEntries` are reads that may drive downstream verification decisions. `SignedChainHead` and `SignedAuditEntriesEnvelope` (signed envelopes, not chained) are the correct category — they attest "at T, the head was H" without growing the chain on every dashboard poll.
- `VerifyChainIntegrity` and `ReconstituteTrustState` are state-transforming operations (they establish a claim about the chain's integrity), so full receipt is appropriate.
- `TailAuditEntries` subsumes the SSE audit-event portion of `events/stream`. The SSE infrastructure path stays.
- `AnchorChainHead` has no current HTTP route; `anchor_pipeline.rs` exists internally. Surfaced as a gap — the anchoring work (Part II.12) needs an operator-invocable verb.
- `GetSystemState` is included here (not NodeStatus) because system state is derived from the receipt chain, making it Audit-service work.

**Dev-tools only (retire entirely):**
- `POST /api/v1/audit/simulate-tamper`, `POST /api/v1/audit/restore`, `POST /api/v1/audit/clear` — feature-flagged, never ship in a verb set.

---

## 5. Mesh

| Verb | Description | Request | Response | Streaming? | Subsumes |
|---|---|---|---|---|---|
| `AnnounceAgent` | Broadcast agent capabilities to the mesh | `AnnounceAgentRequest` | `SignedAnnounce` | no | mesh `EnvelopeType::AgentAnnounce` |
| `SendHeartbeat` | Send a signed liveness heartbeat to a registry | `SendHeartbeatRequest` | `SignedHeartbeat` | no | `POST /api/v1/fleet/heartbeat`, mesh (implicit liveness) |
| `AdvertisePolicy` | Broadcast loaded policy module metadata to mesh peers | `AdvertisePolicyRequest` | `SignedPolicyAdvertisement` | no | mesh `EnvelopeType::PolicyAdvertisement` |
| `ProposePolicy` | Propose a policy for governing a mesh link | `ProposePolicyRequest` | `SignedPolicyProposal` | no | mesh `EnvelopeType::PolicyProposal` |
| `VotePolicy` | Vote on a policy proposal | `VotePolicyRequest` | `PolicyVoteReceipt` | no | mesh `EnvelopeType::PolicyVote` |
| `FinalizePolicy` | Record finalized policy agreement for a mesh link | `FinalizePolicyRequest` | `PolicyAgreementReceipt` | no | mesh `EnvelopeType::PolicyAgreement` |
| `ChallengeAudit` | Send an audit challenge to a peer requesting chain segments | `ChallengeAuditRequest` | `SignedAuditChallenge` | no | mesh `EnvelopeType::AuditChallenge` |
| `RespondAuditChallenge` | Respond to a peer audit challenge with chain segments | `RespondAuditChallengeRequest` | `SignedAuditResponse` | no | mesh `EnvelopeType::AuditResponse` |
| `AttestPeerAudit` | Attest that a peer's audit chain was verified | `AttestPeerAuditRequest` | `AttestationReceipt` | no | mesh `EnvelopeType::AuditAttestation` |
| `BroadcastReputationSummary` | Broadcast a reputation summary about a peer | `BroadcastReputationRequest` | `SignedReputationSummary` | no | mesh `EnvelopeType::ReputationSummary` |
| `TransferReceiptChain` | Transfer a receipt chain segment to another peer | `TransferReceiptChainRequest` | `SignedReceiptChainEnvelope` | no | mesh `EnvelopeType::ReceiptChain` |

**Notes:**
- The 17 `EnvelopeType` mesh variants map 1:1 here; the Mesh service is where they live because they are mesh-wire operations. Some (`AuditAttestation`, `PolicyVote/Agreement`) produce full receipts because they are state-changing — a peer's audit attestation is a chained claim.
- `PolicyPullRequest` / `PolicyPullResponse` / `PolicyChunk` (mesh types 0x11, 0x12, 0x16) are data-transfer sub-operations of the `AdvertisePolicy` → pull flow. They are not distinct verbs — they are the implementation of module sync. Not listed as verbs; they belong inside the Mesh service's transport layer.
- The HTTP fleet policy-push and rollout routes (`/api/v1/fleet/policy/*`) are partial duplicates of the mesh policy-propagation flow. See open questions.

---

## 6. Subscriptions

| Verb | Description | Request | Response | Streaming? | Subsumes |
|---|---|---|---|---|---|
| `Subscribe` | Register a filter + outbound target to receive matching receipts | `SubscribeRequest` | `SubscriptionReceipt` | no | *(no current HTTP route — capability gap)* |
| `Unsubscribe` | Cancel a subscription by ID | `UnsubscribeRequest` | `CancellationReceipt` | no | *(no current HTTP route — capability gap)* |
| `ListSubscriptions` | Return active subscriptions for this node | `ListSubscriptionsRequest` | `SubscriptionsEnvelope` | no | *(no current HTTP route — capability gap)* |
| `RegisterChannelWebhook` | Register a Slack/Discord channel webhook as a subscription target | `RegisterChannelWebhookRequest` | `SubscriptionReceipt` | no | `POST /api/v1/channels/slack/webhook` (partially — see note) |

**Notes:**
- The Subscriptions service has the most gaps relative to the current codebase. `/api/v1/channels/slack/webhook` receives inbound Slack events (it is the subscriber, not the publisher); this is somewhat inverted. The verb-set model makes ZP the publisher and external systems the subscribers. `RegisterChannelWebhook` here means "register a Slack URL as a target to push receipts to." The existing handler is a receiver, not the verb.
- `GET /api/v1/channels/status` is dashboard glue. Retire (see below).
- Delivery 4.7 (webhook, Reticulum push, gossipsub) is expressed entirely via `Subscribe` / `Unsubscribe`; the transport selection is a field of `SubscribeRequest`, not a separate verb per transport.

---

## 7. NodeStatus

| Verb | Description | Request | Response | Streaming? | Subsumes |
|---|---|---|---|---|---|
| `GetIdentity` | Return the node's cryptographic identity (public key, bead zero) | `GetIdentityRequest` | `SignedIdentity` | no | `GET /api/v1/identity`, `GET /api/v1/genesis` |
| `GetNodeStats` | Return runtime statistics (receipts issued, chain length, uptime) | `GetNodeStatsRequest` | `NodeStatsEnvelope` | no | `GET /api/v1/stats` |
| `GetSecurityPosture` | Return the node's security posture assessment | `GetSecurityPostureRequest` | `SignedSecurityPosture` | no | `GET /api/v1/security/posture` |
| `GetTopology` | Return the mesh topology view from this node | `GetTopologyRequest` | `SignedTopologyEnvelope` | no | `GET /api/v1/security/topology` |
| `RegisterBlastRadius` | Register a key-compromise blast-radius record | `RegisterBlastRadiusRequest` | `BlastRadiusReceipt` | no | `POST /api/v1/security/blast-radius/register` |
| `GetBlastRadius` | Query blast-radius impact for a key | `GetBlastRadiusRequest` | `SignedBlastRadiusEnvelope` | no | `GET /api/v1/security/blast-radius/:key` |
| `ReportCompromise` | Report a key compromise event | `ReportCompromiseRequest` | `CompromiseReceipt` | no | `POST /api/v1/security/compromise` |
| `ListFleetNodes` | List all fleet nodes registered with this node | `ListFleetNodesRequest` | `FleetNodesEnvelope` | no | `GET /api/v1/fleet/nodes`, `GET /api/v1/fleet/summary` |
| `GetFleetNode` | Return detail for a single fleet node | `GetFleetNodeRequest` | `SignedFleetNodeEnvelope` | no | `GET /api/v1/fleet/nodes/:id` |
| `DeregisterFleetNode` | Remove a fleet node from the registry | `DeregisterFleetNodeRequest` | `NodeDeregistrationReceipt` | no | `DELETE /api/v1/fleet/nodes/:id` |

**Notes:**
- `GetIdentity` subsumes both `/identity` and `/genesis`. Genesis is the node's founding event; identity is derived from it. Same fact, two endpoints.
- `GetNodeStats`, `GetTopology`, `ListFleetNodes`, `GetFleetNode` are observation-only reads that should not grow the chain on every call. Plain envelope (`NodeStatsEnvelope`, `FleetNodesEnvelope`) is correct for these.
- `GetSecurityPosture`, `GetBlastRadius` are answers that may drive downstream trust decisions — signed envelope is appropriate.
- `RegisterBlastRadius`, `ReportCompromise` are state-changing events — full receipts.
- Fleet rollout management (`/fleet/policy/rollouts`, `/fleet/policy/push`) is addressed in open questions below.

---

## Routes that retire

These HTTP routes do not become verbs. Reasons: dashboard-glue (present only because the current HTTP API serves a JS dashboard), dev-tools-only, or duplicates retired under II.4.

| Route | Reason |
|---|---|
| `GET /` | Dashboard redirect; 4.1/4.2 delivery handles this via native UI or pixel stream |
| `GET /dashboard` | Dashboard HTML; replaced by 4.1/4.2 delivery |
| `GET /speak` | TTS dev tool; not a substrate operation |
| `GET /ecosystem` | Knowledge graph visualization; dashboard-internal |
| `GET /bridge` (+ `/wss`) | Bridge UI HTML + WebSocket upgrade; Bridge-specific delivery, not a substrate verb |
| `GET /api/v1/channels/status` | Dashboard tile glue; channel health is a subscription-layer concern surfaced via `ListSubscriptions` |
| `POST /api/v1/chat`, `POST /api/v1/conversations` | Pipeline/chat endpoints; LLM conversation management is outside ZP's substrate scope |
| `GET /api/v1/tools`, `POST /api/v1/tools/register`, `POST /api/v1/tools/:name/unregister` | Tool registry CRUD; dashboard-glue in the current model. Under verb-set model, tool configuration is Delegation or Guard service work — but at this altitude the tool registry is internal state, not an SDK-facing verb. Retire the HTTP surface; expose via `GetSystemState` if needed. |
| `POST /api/v1/tools/launch`, `POST /api/v1/tools/stop` | Tool lifecycle; cockpit-UI-specific; not a substrate verb |
| `GET /api/v1/tools/log` | Tool log streaming; dashboard-glue |
| `GET /api/v1/tools/:name/probe` | TCP probe for CSP-clean dashboard polling; collapses to zero under native/pixel-stream UI |
| `POST /api/v1/tools/preflight` (POST + GET), `POST /api/v1/tools/:name/preflight` | Preflight is onboarding-ceremony work, not a running-node verb |
| `POST /api/v1/tools/:name/configure`, `POST /api/v1/tools/:name/repair`, `POST /api/v1/tools/:name/reconfigure` | Tool configuration CRUD; internal cockpit ops, not SDK-facing verbs |
| `GET /api/v1/tools/:name/receipts/configured` | Sidecar query; tool-internal; accessible via `QueryAuditEntries` with filter |
| `GET /api/v1/tools/ports` | Port assignment table; CSP workaround; retires with dashboard |
| `GET /api/v1/tools/chain` | Tool chain read; accessible via `QueryAuditEntries` |
| `POST /api/v1/tools/:name/resolve` | Tool resolution; cockpit-specific |
| `POST /api/v1/memory/observe` | Memory pipeline input; an internal cognition verb, not an SDK verb in current form. See note below. |
| `POST /api/v1/cognition/observe`, `POST /api/v1/cognition/reflect` | Cognition pipeline; internal to the node's self-monitoring, not an SDK-facing verb |
| `GET /api/v1/cognition/status`, `GET /api/v1/cognition/observations` | Cognition state; dashboard-glue |
| `GET /api/v1/cognition/reviews`, `POST /api/v1/cognition/reviews`, `POST /api/v1/cognition/reviews/sweep`, `POST /api/v1/cognition/reviews/:id/decide` | Human-review gate; internal workflow, not an SDK verb surface |
| `GET /api/v1/analysis/index`, `GET /api/v1/analysis/expertise`, `GET /api/v1/analysis/tools`, `POST /api/v1/analysis/simulate` | MLE STAR + Monte Carlo analysis; dashboard-internal intelligence layer. These are interesting but not load-bearing for the verb set in Phase 1. Candidate for a future Analytics service. |
| `GET /api/v1/codebase/tree` | Codebase introspection; prod-unsafe (AUTHZ-VULN-13), retire |
| `GET /api/v1/codebase/read`, `GET /api/v1/codebase/search` | Dev-tools only (feature-flagged); retire |
| `POST /api/v1/audit/simulate-tamper`, `POST /api/v1/audit/restore`, `POST /api/v1/audit/clear` | Dev-tools only (feature-flagged); never ship |
| `POST /api/v1/analytics/event`, `GET /api/v1/analytics/course` | Course analytics; public-website concern (`zeropoint.global`), not node-substrate |
| `GET /api/v1/fleet/policy/rollouts`, `GET /api/v1/fleet/policy/rollouts/:id`, `POST /api/v1/fleet/policy/rollouts/:id/ack` | Policy rollout status is partially subsumed by the Mesh service's `AdvertisePolicy` / `FinalizePolicy` verbs. The HTTP-facing rollout management is dashboard-glue for the fleet operator; retire in favor of mesh-native propagation. |
| `POST /api/v1/fleet/policy/push` | Fleet policy push over HTTP; subsumed by `AdvertisePolicy` + `ProposePolicy` on mesh wire |
| `GET /onboard`, `GET /api/onboard/ws` | Onboarding ceremony UI + WebSocket; delivery-4.1/4.2 concern, not a running-node verb |
| `GET /ws/exec` | Cockpit terminal WebSocket; UI delivery concern |

**Count: ~44 routes retire.**

---

## Routes that stay as infrastructure resources

These are not verbs. They live on a documented allowlist per Architecture Part III.

| Path | Why it stays |
|---|---|
| `GET /api/v1/health` | Health probe for load balancers, process supervisors, and CLI `--wait-for-node` checks. No receipt. |
| `GET /api/v1/version` | Version disclosure for compatibility checks. No receipt. |
| `GET /api/v1/events/stream` (SSE) | SSE transport backing `WatchReceipts` and `TailAuditEntries` streaming verbs (delivery 4.3). The SSE path itself is infrastructure; the verb declarations are what make it disciplined. |
| `POST /webrtc/signal` (to-be-added) | WebRTC SDP signaling for delivery 4.2 (pixel-streamed UI). No receipt; covered by Seam 3 TOFU. |
| `GET /assets/*` | Static asset serving. |

---

## Open questions

### Reads as receipts vs. signed envelopes

The three-category framework from Architecture VII.3 resolves this per-verb. Applying it to the reads in this inventory:

| Verb | Category chosen | Justification |
|---|---|---|
| `GetChainHead` | `SignedChainHead` | Drives downstream verification (a verifier cites the chain head as the bound). Signed but not chained — the chain doesn't need to record every read of its own head. |
| `QueryAuditEntries` | `SignedAuditEntriesEnvelope` | Same logic as `GetChainHead`. The response is attestable ("at T, entries E1..En existed") but polling should not grow the chain. |
| `GetIdentity` | `SignedIdentity` | Identity answers drive trust decisions (who am I talking to?). Signed; not chained. An unsigned identity response would be structurally weaker than the architecture claims. |
| `GetSecurityPosture` | `SignedSecurityPosture` | Posture drives operational decisions; signed attestation is warranted. Not chained — every posture poll creating a receipt would bloat the chain. |
| `ListFleetNodes`, `GetNodeStats`, `GetTopology`, `GetBlastRadius` | Plain envelope (`*Envelope`) | Observation-only. These don't drive trust-critical decisions in the same way; fast-polling by dashboards or monitoring tools makes chained receipts impractical. |
| `VerifyChainIntegrity`, `ReconstituteTrustState` | `AttestationReceipt` / `ReconstitutionReceipt` | Full receipt: these are explicit trust-establishing operations that should be auditable. A node that re-verified its chain integrity at T is a fact worth chaining. |

**Unresolved tension:** `QueryAuditEntries` returns a signed envelope but its content *is* the chain. If an external verifier wants to cite "I queried entries E1..En and they were valid," a signed envelope is sufficient — they verify the node's signature on the envelope. If they want *their* act of querying to be in the chain, that's a `VerifyChainIntegrity` call instead. This distinction should be explicit in the schema comments.

### Cross-service verbs

**`VerifyDelegationChain` (Delegation service):** The handler currently lives alongside grant and delegate. But chain verification is auditable-read work — it crosses into Audit territory. Proposed resolution: keep it in Delegation service because the *inputs* are delegation-domain (grant IDs, capability chain), but the response type is `SignedDelegationChainVerification` (signed envelope), consistent with reads that drive trust decisions. If verification produces a chained receipt, move it to Receipts service.

**`AttestPeerAudit` (Mesh service vs. Audit service):** This verb produces an `AttestationReceipt` (full chained receipt). The *trigger* is mesh-based (responding to a `ChallengeAudit` from a peer); the *effect* is a new chain entry on the local node. Natural service home is ambiguous. Proposed: Mesh service issues the verb (because the trigger is mesh-protocol); the receipt is generated by the shared receipt-issuance machinery (no Audit-service-specific logic needed for issuance). The Audit service's `VerifyChainIntegrity` is the local-chain variant; `AttestPeerAudit` is the cross-node variant.

**`ProxyCall` (Guard service vs. Receipts service):** The proxy intercepts LLM API calls, applies policy (`EvaluateGate`), and generates a receipt. It is clearly a gate-adjacent operation. Kept in Guard service. If `ProxyCall` grows to subsume arbitrary non-LLM external calls, it may warrant its own service; not there yet.

**Fleet policy distribution (`/fleet/policy/push`, rollout routes):** These are HTTP-facing proxies over what should be native mesh operations (`AdvertisePolicy`, `ProposePolicy`, `FinalizePolicy`). The HTTP surface retires; the fleet operator drives policy distribution via the Mesh service verbs. The rollout tracking state (which nodes acknowledged which policy version) is internal Mesh-service bookkeeping, not an SDK-facing verb.

### Architectural surprises

1. **The cognition pipeline has no verb-set home.** `POST /api/v1/cognition/observe`, `reflect`, `reviews/*` are a substantial subsystem (G5-1, G5-2) with no clean fit in any of the 7 services. It is neither Guard (not policy evaluation), nor Delegation, nor Receipts, nor Audit (it *uses* the chain but doesn't expose it), nor Mesh, nor NodeStatus. This looks like an 8th service — a future **Cognition service** or **Observability service** — or it is delivery-4.1/4.2-only internal machinery that never surfaces as a verb. The architecture doc does not address this subsystem; it may be intentional internal-only tooling or an early prototype of the cognitive accountability Layer 3 vision (`docs/future-work/cognitive-accountability.md`). Flag: do not assign cognition routes to any of the 7 services without an explicit decision.

2. **The analysis engines (MLE STAR + Monte Carlo) are receipt-native but have no verb-set home.** `analysis.rs` already emits receipts ("every query emits a receipt"). This is the most forward-looking part of the codebase relative to the verb-set architecture. Like cognition, it has no home in the 7 services. Future Analytics service, or collapse into Audit service queries. Flagged for Ken's call.

3. **`POST /api/v1/receipts` (external) vs. `POST /api/v1/receipts/generate` are semantically distinct.** `receipts/generate` issues a new receipt; `receipts` (external) accepts a receipt from an external source for ingestion. The ingestion path is not clearly modeled in the verb set — `GenerateReceipt` covers issuance, but "accept an external receipt" may warrant a separate `IngestReceipt` verb in the Receipts service. The current inventory merges them; flagged as a potential split.

4. **`WithdrawCapability` has no current implementation.** V.3 in the architecture doc explicitly calls delegation withdrawal an open dimension. The verb slot is reserved above, but the mechanics decision (TTL vs. dead-man's-switch vs. quorum-revocable) must precede any proto definition for this verb. The inventory marks the gap; don't write the proto field until V.3 is resolved.

5. **`AnchorChainHead` has no current HTTP route.** `anchor_pipeline.rs` exists but appears to be internal background work. The verb-set model implies an operator should be able to explicitly trigger an anchoring operation (or at least inspect anchoring state). Gap between the architectural commitment (Part II.12, OpenTimestamps) and the current HTTP surface.

---

## Verb count summary

| Service | Verbs | Full receipts | Signed envelopes | Plain envelopes | Streaming |
|---|---|---|---|---|---|
| Guard | 9 | 7 | 2 | 0 | 0 |
| Delegation | 6 | 4 | 1 | 0 | 0 |
| Receipts | 6 | 4 | 1 | 0 | 1 |
| Audit | 7 | 4 | 2 | 1 | 1 |
| Mesh | 11 | 4 | 7 | 0 | 0 |
| Subscriptions | 4 | 3 | 0 | 1 | 0 |
| NodeStatus | 10 | 4 | 4 | 2 | 0 |
| **Total** | **53** | **30** | **17** | **4** | **2** |

*Routes retiring: ~44. Routes staying as infrastructure: 5.*
