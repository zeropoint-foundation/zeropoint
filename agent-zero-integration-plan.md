# ZeroPoint × Agent Zero Integration Plan

## The Opportunity

Agent Zero's memory system uses FAISS vector search with four memory categories (storage, fragments, solutions, metadata). Joshua wants to integrate FalkorDB (graph database) and Graphiti (Zep's temporal knowledge graph) for richer, relationship-aware agent memory. ZeroPoint can govern the entire memory layer — making every memory assertion verifiable, every access scoped, and every cross-agent memory share provable.

**The pitch**: ZeroPoint doesn't replace FalkorDB or Graphiti — it governs them. Every triple written to the graph becomes a signed receipt. Every query is capability-scoped. Every memory shared between agents is verifiable. FalkorDB is the storage. Graphiti is the temporal model. ZeroPoint is the trust.

---

## Architecture Fit

### Agent Zero's Extension Points (our integration surface)

| Entry Point | What it does | How ZP plugs in |
|-------------|-------------|-----------------|
| **Extensions** (`python/extensions/`) | Hooks into the message loop by phase. Files run in alpha order. | `zp_memory_guard.py` — intercepts memory writes, wraps in signed receipts |
| **Custom Tools** | Tools are prompt files + optional Python class. | `zp_memory_tool` — governed read/write replacing native `memory_tool` |
| **Agent Profiles** (`agents/<name>/`) | Override prompts per agent/subagent. | Each agent profile gets a ZP capability grant defining its memory scope |
| **behaviour.md** | Rules stored in memory directories. | ZP policy rules expressed as behaviour.md, enforced cryptographically |
| **Knowledge imports** | .txt, .pdf, .csv, .json, .md into memory. | Every import produces a receipt chain — provenance from source to memory |

### Memory Flow: Before and After

**Before (current A0):**
```
Agent → memory_tool → FAISS vector store
                   → (proposed) FalkorDB graph
                   → (proposed) Graphiti temporal layer
```

**After (with ZP):**
```
Agent → zp_memory_tool → Guard (policy check)
                       → Receipt (sign the assertion)
                       → FalkorDB/Graphiti (store the graph triple + receipt)
                       → Audit (hash-chain the write)
                       → Return (with receipt ID as provenance)
```

Every memory operation flows through Guard → Policy → Store → Audit. The agent gets its memory. ZeroPoint gets the proof.

---

## Integration Components

### 1. ZP Memory Extension (`python/extensions/zp_memory_guard.py`)

Runs in A0's extension framework. Intercepts memory operations at the message loop level.

**What it does:**
- Wraps every `memory_tool` call in a ZP receipt
- Signs with the agent's Ed25519 identity (each agent/subagent gets its own key)
- Hashes into the audit chain
- Enforces capability grants (Agent B can only read memories in scopes it was granted)

**Extension hook point:** `msg_loop` phase, runs before the native memory extension.

### 2. ZP Memory Tool (`zp_memory_tool`)

Replaces or wraps A0's native `memory_tool` with governed memory operations.

**Operations:**
- `remember(fact, scope, confidence)` → produces a signed receipt, stores in graph
- `recall(query, scope)` → checks capability grants, returns results with provenance
- `share(receipt_id, target_agent, scope, ttl)` → delegates read capability to subagent
- `verify(receipt_id)` → validates receipt signature and chain integrity
- `retract(receipt_id, reason)` → creates a retraction receipt (original stays, marked superseded)

### 3. Agent Identity (`zp_agent_identity.py`)

Each A0 agent and subagent gets a ZP mesh identity.

- **Agent 0 (root)**: Generates Ed25519 keypair on first run, stored at `~/.agent-zero/zp-identity.key`
- **Subagents**: Receive delegated identities from their parent agent
- **Identity = capability boundary**: What an agent can remember and recall is defined by its capability grants, not by having access to the whole vector store

### 4. FalkorDB Receipt Layer

Wraps FalkorDB writes so every graph triple carries a receipt.

```
CREATE (fact:Memory {
  content: "User prefers dark mode",
  receipt_id: "rcpt-a1b2c3",
  signer: "agent0-dest-hash",
  signature: "ed25519-sig-hex",
  chain_hash: "blake3-prev-hash",
  trust_grade: "B",
  valid_from: timestamp,
  valid_until: null
})
```

Graphiti's temporal model maps naturally: `valid_from` / `valid_until` on receipts align with Graphiti's bi-temporal validity windows. A retraction receipt sets `valid_until` on the original.

### 5. Capability Grants for Memory Scopes

When Agent 0 delegates to a subagent:

```python
grant = CapabilityGrant(
    grantor="agent0",
    grantee="subagent-research",
    capability=Read(scope=["project-X/*", "user-preferences/*"]),
    ttl=300,  # 5 minutes
    max_delegation_depth=1  # subagent can share with one level down
)
```

The subagent can only recall memories in its granted scopes. When the task completes, the grant expires. No residual access.

---

## Implementation Phases

### Phase 1: Receipt-Wrapped Memory (Week 1)
**Goal:** Every memory write produces a signed receipt. No behavior change for the agent — it just gets provenance for free.

- [ ] Create `zp_memory_guard.py` A0 extension
- [ ] Generate agent identity on first run
- [ ] Wrap `memory_tool.save` with receipt signing
- [ ] Store receipts alongside FAISS vectors (metadata field)
- [ ] Add `verify` command to check receipt chain integrity
- [ ] Smoke test: agent remembers a fact, receipt is verifiable

### Phase 2: Scoped Access (Week 2)
**Goal:** Subagents get capability-scoped memory access instead of full vector store access.

- [ ] Implement `zp_memory_tool` with scope-aware `recall`
- [ ] Add capability grants to `call_subordinate` flow
- [ ] Parent agent issues grants when delegating; subagent checks grants on recall
- [ ] Grant expiry on task completion
- [ ] Test: subagent can recall in-scope memories, blocked on out-of-scope

### Phase 3: FalkorDB + Graphiti Integration (Week 3-4)
**Goal:** Graph-backed memory with temporal provenance, governed by ZP.

- [ ] FalkorDB node/edge schema with receipt fields
- [ ] Graphiti temporal model aligned to receipt validity windows
- [ ] Graph-aware `recall` — traverse relationships, not just vector similarity
- [ ] Contradiction detection via receipt chain divergence
- [ ] Cross-agent memory sharing with delegated capability grants

### Phase 4: Mesh Participation (Week 4+)
**Goal:** Agent Zero joins the ZP trust mesh as a first-class peer.

- [ ] AgentAnnounce envelope on A0 startup (capabilities: memory-governance, tool-execution)
- [ ] A0 appears in Bridge topology view alongside Sentinel, Core, etc.
- [ ] Receipt exchange between A0 agents and other mesh peers
- [ ] Agents from different frameworks can verify each other's memory claims

---

## File Structure

```
agent-zero/
├── python/extensions/
│   ├── 10_zp_identity.py          # Generate/load agent identity
│   ├── 15_zp_memory_guard.py      # Receipt-wrap memory operations
│   └── 16_zp_capability_check.py  # Enforce scope grants on recall
├── python/tools/
│   └── zp_memory_tool.py          # Governed memory tool
├── agents/default/prompts/
│   └── agent.system.tool.zp_memory.md  # Tool prompt
├── zp_config.toml                 # ZP integration config
└── .zp-identity/                  # Agent keypairs (gitignored)
    ├── agent0.key
    └── subagents/
```

---

## Config (`zp_config.toml`)

```toml
[zp]
# ZeroPoint Core for mesh participation (optional)
# core_url = "http://localhost:3000"

# Identity
identity_dir = ".zp-identity"

# Memory governance
sign_all_memories = true
enforce_capability_scopes = true
default_memory_ttl = 0           # 0 = no expiry

# FalkorDB (when integrated)
# falkordb_url = "redis://localhost:6379"
# graphiti_enabled = true

[zp.audit]
# Local audit chain
db_path = ".zp-identity/audit.db"
chain_algorithm = "blake3"       # blake3 or sha256
```

---

## What Joshua Gets

1. **Week 1**: Drop-in extension that adds cryptographic provenance to every memory operation. No breaking changes. Agent Zero works exactly as before, but now every memory has a verifiable receipt.

2. **Week 2**: Subagents get scoped access instead of the full memory store. Parent agents control what subordinates can see. Grants expire when tasks complete.

3. **Week 3-4**: Graph-backed memory via FalkorDB + Graphiti, with temporal provenance aligned to ZP receipts. Contradiction detection. Cross-agent memory sharing with proof.

4. **Week 4+**: Agent Zero becomes a mesh peer. Its memory claims are verifiable by any other ZP component — Sentinel, Core, other agent frameworks. Portable proof across trust boundaries.

---

## The Onramp

This follows the Sentinel pattern: solve a problem someone already has (governed agent memory), and let ZeroPoint's trust primitives prove themselves through use.

Joshua gets better memory for Agent Zero. ZeroPoint gets embedded in an active agent framework with a developer community. Both projects benefit.

The Sentinel governs the network edge. This integration governs the agent memory layer. Same protocol. Same receipts. Same mesh. Different onramp, same trust fabric.

**One protocol. One graph. End to end.**

---

*ZeroPoint: [zeropoint.global](https://zeropoint.global) · [GitHub](https://github.com/zeropoint-foundation/zeropoint)*
*Agent Zero: [agent-zero.ai](https://www.agent-zero.ai/) · [GitHub](https://github.com/agent0ai/agent-zero)*
