# Regent Vault Interface & Gossip System Integration

**Date:** 2026-07-08
**Status:** Design draft
**Author:** Ken Romero, with synthesis assistance from Claude
**Depends on:** ARCHITECTURE-2026-07.md, regent-gossip-and-evolution-2026-07.md, EXECUTION-AUTHORITY-MODEL-2026-07.md, VAULT-INTEGRITY-SYSTEM-2026-06.md

---

## Part I: Regent Vault Interface

### 1. Problem

The Regent's `self_configure` tool currently accepts `api_key` as a raw parameter. The key flows through the Regent's cognitive context (in-memory config struct), and while the receipt itself only records model names, the key's presence in the cognitive path means it could leak into chain entries through observation receipts, Regent reasoning traces, or tool output that gets serialized. The Sentinel correctly flags this as a Critical finding (`secret_in_chain`), producing a persistent 60% security posture score.

The structural fix: API keys belong in the vault, not in the cognitive path. The Regent needs a governed interface to the vault — scoped, audited, and composing with the existing tier system.

### 2. Design: Scoped Vault Access

The vault already has the right primitives:

- **`VaultTier::System`** — internal ZP operational secrets, with its own derived encryption key.
- **`VaultScope`** — prefix-constrained, tier-isolated read/write views.
- **`VaultScopeRef`** — immutable read-only scoped views.
- **`store_ref()`** — vault references that follow edges across tiers (a system-tier entry can reference a providers-tier API key).

The Regent gets a **read-scoped vault accessor** at `system/regent/` and a **write path gated by the governance receipt system**. She never sees the secret value in her cognitive context.

#### 2.1 Vault Path Convention

```
system/regent/inference/api_key        → the actual encrypted key (or ref to providers/*)
system/regent/inference/endpoint       → inference endpoint URL
system/regent/gossip/social_allowance  → current social allowance pool state
system/regent/gossip/compute_allowance → current compute allowance pool state
```

The `system/regent/` prefix scopes all Regent-managed vault entries. The `VaultScope` mechanism enforces that the Regent's accessor can only read/write within this prefix (with ref-following for cross-tier reads like API keys stored in `providers/`).

#### 2.2 Access Pattern

```rust
/// In ServerIntentExecutor:
struct ServerIntentExecutor {
    // ... existing fields ...
    
    /// Vault key for scoped access. The Regent never holds the master key —
    /// she holds a resolved vault key from which scoped accessors are derived.
    vault_key: Option<zp_keys::ResolvedVaultKey>,
    
    /// Path to vault.json on disk.
    vault_path: PathBuf,
}
```

The vault is loaded, scoped, used, and dropped within a single tool dispatch — no persistent vault handle. The Regent's cognitive context never sees secret values.

```rust
// In self_configure dispatch:
"self_configure" => {
    // API key handling: vault-mediated, never cognitive
    if let Some(raw_key) = params.get("api_key").and_then(|v| v.as_str()) {
        // Write the key to vault, not to in-memory config
        if let Some(ref vk) = self.vault_key {
            let mut vault = CredentialVault::load_or_create(&vk.key, &self.vault_path)?;
            vault.store_tiered(
                "system/regent/inference/api_key",
                raw_key.as_bytes(),
                VaultTier::System,
            )?;
            vault.save(&self.vault_path)?;
            // The key is now in the vault. The Regent's config gets a marker, not the value.
            // The inference backend reads from vault at call time.
        }
    }
    
    // Model/endpoint changes still go through reconfigure_inference,
    // but api_key is no longer a parameter — it's vault-mediated.
    // ...
}
```

#### 2.3 Inference Backend Reads from Vault

The `InferenceBackend::new()` constructor currently takes the API key from `RegentConfig.inference_api_key`. Under the new design:

1. `RegentConfig.inference_api_key` becomes `Option<VaultKeyRef>` — a marker indicating "there's a key in the vault" without holding the value.
2. At inference call time, the backend resolves the key from vault: `vault.retrieve("system/regent/inference/api_key")`.
3. The resolved key is used for the HTTP call and immediately dropped. It never enters the Regent's observation pipeline, reasoning output, or chain receipts.

```rust
/// Marker type — indicates vault has a key, doesn't hold the value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiKeySource {
    /// No API key — using Ollama or local inference.
    None,
    /// Key stored in vault at this path.
    Vault(String),
}
```

#### 2.4 Receipt Shape

The `regent:config:inference` receipt changes from:

```
reasoning=qwen3:8b routing=qwen3:1.7b
```

to:

```
reasoning=claude-sonnet-4-6 routing=qwen3:1.7b endpoint=api.anthropic.com api_key_source=vault:system/regent/inference/api_key
```

The receipt documents *where* the key lives, not *what* it is. The Sentinel's `secret_in_chain` check passes because no key pattern appears in the serialized receipt.

#### 2.5 Migration Path

1. On first startup after the change, if `RegentConfig.inference_api_key` contains a raw key (from `config.toml`), migrate it to vault automatically and replace the config field with `ApiKeySource::Vault(...)`.
2. Emit a `regent:config:vault_migration` receipt documenting the migration.
3. The `config.toml` field `regent.inference_api_key` becomes deprecated — documented as "use `zp configure vault-set` for API keys" in the config comments.
4. Sentinel's posture score recovers to 1.0 in the security domain once the chain entry with the raw key ages out of the 500-entry scan window.

#### 2.6 Composition with Singular Sovereign Root

The vault key resolves from the same sovereign root as everything else — one Touch ID prompt at process start, the master key unlocks the vault, the Regent's scoped accessor derives from the master key via `VaultTier::System`. No additional authentication prompts. The Regent's vault access is a projection of the operator's sovereign authentication, not an independent credential.

---

## Part II: Gossip System Code Mapping

### 3. Crate Structure

The gossip system introduces one new crate and touches three existing ones.

#### 3.1 New: `zp-gossip`

```
crates/zp-gossip/
├── Cargo.toml
└── src/
    ├── lib.rs              # Public API surface
    ├── finding.rs          # GossipFinding, FindingType, FindingPayload
    ├── allowance.rs        # SocialAllowance, ComputeAllowance, regeneration
    ├── inbox.rs            # FindingInbox — reception, dedup, intake limiting
    ├── verification.rs     # Local verification pipeline
    ├── zone.rs             # Zone classification (Zone1/Zone2/Zone3)
    └── transport.rs        # Trait for finding exchange (store-and-forward)
```

**Dependencies:** `zp-core` (types, hashing), `zp-audit` (receipt emission), `chrono`, `serde`, `blake3`.

No dependency on `zp-mesh`. The gossip layer is a higher-level abstraction that *uses* mesh transport when available, but the core types and allowance logic are independent. A substrate with no mesh connectivity can still produce and consume gossip findings through manual export/import.

#### 3.2 Core Types

```rust
// finding.rs

/// Content-addressed gossip finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipFinding {
    pub finding_id: ContentHash,
    pub finding_type: FindingType,
    pub created_at: DateTime<Utc>,
    pub model_family: String,
    pub model_variant: Option<String>,
    pub payload: FindingPayload,
    pub substrate_version: String,
    pub evaluation_receipt_hash: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingType {
    ModelPromptCoupling,
    ConfigurationRecipe,
    PerformanceCharacteristic,
    PromptVariant,
    SafetyBoundary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingPayload {
    ModelPromptCoupling {
        task: String,               // "sovereign_identity", "json_compliance", "think_suppression"
        result: CouplingResult,     // Pass/Fail/Degraded
        prompt_hash: String,        // hash of the prompt variant tested
        conditions: Vec<String>,    // "temperature=0.3", "context_window=4096"
    },
    ConfigurationRecipe {
        parameters: BTreeMap<String, serde_json::Value>,
        use_case: String,           // "structured_output", "conversation", "tool_dispatch"
        measured_improvement: Option<f64>,
    },
    PerformanceCharacteristic {
        hardware_class: String,     // "apple_silicon_m2", "nvidia_4090", "cpu_only"
        latency_ms: Option<f64>,
        tokens_per_second: Option<f64>,
        memory_mb: Option<u64>,
        context_window_tested: Option<u64>,
    },
    PromptVariant {
        base_prompt_hash: String,
        variant_text: String,       // the actual prompt — substrate infrastructure, not operator data
        task: String,
        improvement_over_base: f64, // 0.0–1.0
    },
    SafetyBoundary {
        failure_mode: String,       // "hallucination", "instruction_bypass", "context_overflow"
        trigger_conditions: Vec<String>,
        severity: String,           // "critical", "degraded", "edge_case"
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CouplingResult {
    Pass,
    Fail,
    Degraded { score: f64 },
}
```

#### 3.3 Allowance System

```rust
// allowance.rs

/// Social allowance — controls broadcast rate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialAllowance {
    /// Current pool (units).
    pub current: f64,
    /// Maximum pool size.
    pub max_pool: f64,
    /// Regeneration rate (units per hour).
    pub regen_rate: f64,
    /// Last regeneration timestamp.
    pub last_regen: DateTime<Utc>,
}

/// Compute allowance — controls exploratory inference budget.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeAllowance {
    /// Current pool (inference-seconds).
    pub current: f64,
    /// Maximum pool size.
    pub max_pool: f64,
    /// Base regeneration rate (units per idle-hour).
    pub regen_rate: f64,
    /// Multiplier during maintenance windows.
    pub maintenance_multiplier: f64,
    /// Last regeneration timestamp.
    pub last_regen: DateTime<Utc>,
}

impl SocialAllowance {
    /// Cost to broadcast a finding.
    /// Zone 3 invariant: minimum cost = 2 * regen_rate.
    /// This makes the listen-twice ratio a conservation law.
    pub fn broadcast_cost(&self, _payload_size: usize) -> f64 {
        // Minimum: 2 * regen_rate (the constitutional floor).
        // Larger payloads cost more, but never less than the floor.
        2.0 * self.regen_rate
    }

    /// Regenerate allowance based on elapsed time.
    pub fn regenerate(&mut self) {
        let now = Utc::now();
        let elapsed_hours = (now - self.last_regen).num_seconds() as f64 / 3600.0;
        self.current = (self.current + elapsed_hours * self.regen_rate).min(self.max_pool);
        self.last_regen = now;
    }

    /// Can the Regent afford to broadcast?
    pub fn can_broadcast(&self, payload_size: usize) -> bool {
        self.current >= self.broadcast_cost(payload_size)
    }

    /// Spend allowance on a broadcast.
    pub fn spend(&mut self, payload_size: usize) -> Result<f64, AllowanceError> {
        let cost = self.broadcast_cost(payload_size);
        if self.current < cost {
            return Err(AllowanceError::InsufficientAllowance {
                needed: cost,
                available: self.current,
            });
        }
        self.current -= cost;
        Ok(cost)
    }
}
```

#### 3.4 Intake Limiter (Zone 3)

```rust
// inbox.rs

/// Reception-side intake limiter.
/// Zone 3 property — constitutional, not configurable.
pub struct FindingInbox {
    /// Findings awaiting verification.
    pending: VecDeque<GossipFinding>,
    /// Content hashes of all findings ever seen (dedup).
    seen: HashSet<ContentHash>,
    /// Maximum findings processed per hour (Zone 3 invariant).
    intake_rate: f64,                    // constitutional — not in config.toml
    /// Findings processed in the current window.
    processed_this_window: u64,
    /// Current window start.
    window_start: DateTime<Utc>,
}

impl FindingInbox {
    /// Zone 3 constant: maximum intake rate.
    /// This is NOT configurable. It is the reception-side enforcement
    /// of the listen-twice principle (§5.1 of the gossip design).
    const CONSTITUTIONAL_INTAKE_RATE: f64 = 12.0; // per hour

    pub fn receive(&mut self, finding: GossipFinding) -> ReceiveResult {
        // Dedup by content hash
        if self.seen.contains(&finding.finding_id) {
            return ReceiveResult::Duplicate;
        }

        // Intake limiting (Zone 3)
        self.refresh_window();
        if self.processed_this_window as f64 >= Self::CONSTITUTIONAL_INTAKE_RATE {
            return ReceiveResult::RateLimited;
        }

        self.seen.insert(finding.finding_id.clone());
        self.pending.push_back(finding);
        self.processed_this_window += 1;
        ReceiveResult::Accepted
    }

    /// Next finding ready for verification (costs compute allowance).
    pub fn next_for_verification(&mut self) -> Option<GossipFinding> {
        self.pending.pop_front()
    }
}

pub enum ReceiveResult {
    Accepted,
    Duplicate,
    RateLimited,
}
```

#### 3.5 Zone Classification

```rust
// zone.rs

/// Evolution zone for a proposed change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Zone {
    /// Operational tuning — Regent acts autonomously (with precedent).
    Autonomous,
    /// Structural proposal — requires operator approval.
    Proposal,
    /// Constitutional invariant — requires amendment ceremony.
    Constitutional,
}

/// Classify a finding's influence zone based on what it would change.
pub fn classify_finding(finding: &GossipFinding) -> Zone {
    match &finding.payload {
        FindingPayload::ConfigurationRecipe { parameters, .. } => {
            // If parameters only touch Zone 1 values (temperature, top_p, etc.), autonomous.
            // If they touch model selection or tool config, proposal.
            if parameters.keys().all(|k| is_zone1_param(k)) {
                Zone::Autonomous
            } else {
                Zone::Proposal
            }
        }
        FindingPayload::PromptVariant { .. } => {
            // Prompt variants are Zone 1 if selecting among pre-validated variants,
            // Zone 2 if introducing a new variant.
            Zone::Proposal // conservative default; Regent can downgrade to Autonomous
                           // if she has precedent for this prompt task
        }
        FindingPayload::ModelPromptCoupling { .. } |
        FindingPayload::PerformanceCharacteristic { .. } => {
            // Informational — influences Zone 1 decisions but doesn't require action.
            Zone::Autonomous
        }
        FindingPayload::SafetyBoundary { .. } => {
            // Safety findings are informational but may trigger Zone 2 proposals
            // (e.g., "stop using this model").
            Zone::Proposal
        }
    }
}

fn is_zone1_param(key: &str) -> bool {
    matches!(key,
        "temperature" | "top_p" | "top_k" | "repeat_penalty" |
        "context_window" | "keep_alive" | "num_predict" | "seed"
    )
}
```

### 4. Integration Points

#### 4.1 Regent ← Gossip (cognitive cycle integration)

The Regent's cognitive cycle gains a gossip phase between officer sweep processing and idle maintenance:

```
cognitive_cycle:
  1. Check operator input (preempts everything)
  2. Process officer findings (existing)
  3. Process gossip inbox (NEW)
     - If compute allowance available AND inbox has pending findings:
       - Pop next finding
       - Run local verification
       - If verified: integrate (Zone 1 → apply; Zone 2 → propose)
       - Emit receipt
  4. Idle maintenance (existing — model evaluation sweeps, etc.)
```

The gossip phase respects the priority hierarchy: operator input preempts it, and it yields to memory pressure via the existing harmony system.

#### 4.2 Regent → Gossip (broadcast decision)

After any model evaluation (via `model_evaluate` tool or background sweep), the Regent decides whether to broadcast:

```rust
// In Regent cognitive cycle, after evaluation completes:
if let Some(finding) = evaluation_to_gossip_finding(&eval_result) {
    let zone = classify_finding(&finding);
    if zone == Zone::Autonomous && social_allowance.can_broadcast(finding_size) {
        // Worth broadcasting — novel, useful, and we have allowance
        social_allowance.spend(finding_size)?;
        gossip_transport.broadcast(finding.clone())?;
        emit_receipt("regent:gossip:broadcast", &finding);
    }
}
```

#### 4.3 Memory Pipeline Integration

Received gossip findings enter the existing memory promotion pipeline:

```
GossipFinding received
  → inbox.receive() (dedup + intake limit)
  → verification (costs compute allowance)
  → if verified: ingest as Observed memory with source="gossip"
  → normal promotion lifecycle: Observed → Interpreted → Trusted → Remembered
```

A gossip finding that reaches Trusted has been locally verified and policy-approved. One that reaches Remembered has been reinforced across multiple verification runs. The promotion lifecycle IS the trust model for gossip — no separate trust mechanism needed.

#### 4.4 Transport Layer

```rust
// transport.rs

/// Gossip transport — how findings move between substrates.
/// Store-and-forward, not live. Composes with Principle 5.
pub trait GossipTransport: Send + Sync {
    /// Broadcast a finding to available peers.
    fn broadcast(&self, finding: GossipFinding) -> Result<(), GossipError>;
    
    /// Receive pending findings from peers.
    fn receive(&self) -> Result<Vec<GossipFinding>, GossipError>;
}

/// Mesh-backed transport — uses zp-mesh when available.
pub struct MeshGossipTransport { /* ... */ }

/// File-based transport — export/import for air-gapped substrates.
pub struct FileGossipTransport { /* ... */ }

/// Null transport — gossip disabled, Regent only uses local findings.
pub struct NullGossipTransport;
```

The transport trait decouples the gossip logic from the network layer. A substrate with mesh connectivity uses `MeshGossipTransport`. An air-gapped substrate uses `FileGossipTransport` (operator manually moves finding bundles). A substrate with gossip disabled uses `NullGossipTransport` — the Regent still produces local findings, she just doesn't share them.

### 5. Vault ↔ Gossip Composition

The gossip system uses the vault for two things:

1. **Allowance persistence.** Social and compute allowance state is stored in the vault at `system/regent/gossip/social_allowance` and `system/regent/gossip/compute_allowance`. This survives restarts without putting allowance state on the chain (allowances are operational bookkeeping, not governance acts).

2. **Transport credentials.** If the gossip transport requires authentication (mesh peer keys, relay tokens), those credentials go in the vault at `system/regent/gossip/transport/*`, never in the Regent's cognitive context or on the chain.

The vault scope for gossip is a sub-scope of the Regent's existing `system/regent/` prefix — no new vault tiers, no new access patterns.

### 6. Chain Receipt Types

All new receipt types, consolidated:

| Receipt | Phase | Content |
|---------|-------|---------|
| `regent:config:inference` | Vault | Model/endpoint changes + `api_key_source=vault:path` (never the key itself) |
| `regent:config:vault_migration` | Vault | One-time migration of raw key to vault |
| `regent:gossip:broadcast` | Gossip | `finding_id`, `finding_type`, `social_allowance_spent` |
| `regent:gossip:received` | Gossip | `finding_id`, content hash of source |
| `regent:gossip:verified` | Gossip | `finding_id`, `result` (confirmed/refuted), compute_spent |
| `regent:gossip:integrated` | Gossip | `finding_id`, `zone`, action_taken |
| `regent:evolution:proposal` | Gossip | Proposed Zone 2 change, evidence chain |
| `regent:evolution:applied` | Gossip | Zone 1 change applied, old/new values, evidence |

### 7. Configuration Surface

```toml
[regent.gossip]
# Social allowance — controls broadcast rate
social_regen_rate = 1.0      # units per hour (Zone 2 — operator can tune)
social_max_pool = 24.0       # maximum accumulated units

# Compute allowance — controls exploratory inference budget
compute_regen_rate = 1.0     # units per idle-hour
compute_max_pool = 10.0      # maximum accumulated units
compute_maintenance_mult = 3.0  # multiplier during maintenance windows

# Transport
transport = "mesh"           # "mesh", "file", "none"
# file_export_dir = "~/.zeropoint/gossip/outbox"  # for file transport

[regent.evolution]
proposal_aggressiveness = "medium"  # "low", "medium", "high"
```

Note: `social_regen_rate` and `social_max_pool` are Zone 2 parameters — the operator can tune them, but the *relationship* between them (broadcast cost = 2 × regen_rate) is Zone 3. The operator can make their Regent more or less chatty, but they cannot break the listen-twice ratio without the constitutional amendment ceremony.

### 8. Implementation Phases

**Phase 0 — Vault interface (immediate, fixes the 60% posture score):**
- Add `vault_key` and `vault_path` to `ServerIntentExecutor`.
- Refactor `self_configure` to write API keys to vault, not cognitive context.
- Add `ApiKeySource` enum to `RegentConfig`.
- Modify `InferenceBackend` to resolve keys from vault at call time.
- Migration logic for existing raw keys.

**Phase 1 — Gossip types (pure library, no integration):**
- Create `zp-gossip` crate with `finding.rs`, `allowance.rs`, `zone.rs`.
- Unit tests for allowance regeneration, broadcast cost, zone classification.
- Content-addressing for `GossipFinding` (BLAKE3 of canonical serialization).

**Phase 2 — Inbox and verification:**
- `inbox.rs` with intake limiting and dedup.
- `verification.rs` — runs the finding's claimed test locally using the model evaluation battery.
- Integration with `zp-memory` for ingesting verified findings as Observed memories.

**Phase 3 — Cognitive cycle integration:**
- Add gossip phase to Regent's cognitive cycle.
- Broadcast decision logic after model evaluations.
- Receipt emission for all gossip events.
- Allowance persistence in vault.

**Phase 4 — Transport:**
- `MeshGossipTransport` composing with `zp-mesh`.
- `FileGossipTransport` for manual exchange.
- Integration tests for store-and-forward semantics.

**Phase 5 — Evolution proposals:**
- Zone 2 proposal surfacing through SSE events and Regent chat.
- Operator approval/denial creating precedent receipts.
- Precedent-based autonomous action for repeated Zone 1 patterns.
