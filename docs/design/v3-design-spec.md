# ZEROPOINT v3 DESIGN SPECIFICATION AND BUILD PLAN

## Securing Truth Transitions on Insecure Substrates

Version 1.0 — April 2026
ThinkStream Labs
CONFIDENTIAL

Companion to: `zp-doctrine-memo.md` (constitutional principles),
`ARCHITECTURE.md` (system design), `whitepaper-v2.md` (public thesis)

---

## 0. How to Read This Document

This spec translates the doctrine memo's five security planes into
engineering deliverables. Depth is graduated by maturity:

- **Pathway Plane** — sprint-level: specific functions, files, tests.
  This is where we've been grinding and where the pentest drew blood.
- **Claim Plane** — interface-level: typed receipt signatures, storage
  formats, validation rules. Foundation exists; formalization needed.
- **Meaning Plane** — interface-level: provenance tracking, type system
  evolution for observed/interpreted/admitted distinctions.
- **Cognition Plane** — architecture-level: promotion engine design,
  lifecycle rules. Crate exists with real implementations; integration
  and wiring needed.
- **Compromise Plane** — architecture-level: revocation chains,
  quarantine policy, reconstitution procedures. Some primitives exist;
  design decisions needed before coding.

Each plane section follows the same structure: current state (what
exists in code today), doctrine requirements (what must be true),
gap analysis (what's missing), and build plan (what to do, in order).

---

## 1. Codebase Baseline

As of commit `263f9c6` (April 19, 2026), the workspace contains 28
crates. The project is approximately 80% through the original Phase 2
(Trust & Skills) of the ARCHITECTURE.md roadmap.

### 1.1 Crate Inventory by Plane

**Pathway Plane (enforcement)**:
`zp-server` (Axum router, auth middleware, tool proxy),
`zp-cli` (CLI interface, configure engine),
`zp-engine` (shared scan/configure/vault/provider logic),
`zp-trust` (credential vault, injector, signer),
`zp-hardening-tests` (Shannon regression harness),
`execution-engine` (WASM-sandboxed polyglot exec)

**Claim Plane (cryptographic proof)**:
`zp-receipt` (typed receipts with builder, signer, verifier, chaining),
`zp-keys` (Ed25519 hierarchy: genesis → operator → agent),
`zp-audit` (hash-chained audit trail),
`zp-verify` (receipt and chain verification)

**Meaning Plane (semantic governance)**:
`zp-core` (GovernanceEvent with 35 variants, PolicyDecision, CapabilityGrant, DelegationChain),
`zp-policy` (native Rust rules + WASM policy runtime),
`zp-pipeline` (governance gate: Guard → Policy → Execute → Audit)

**Cognition Plane (machine thought lifecycle)**:
`zp-memory` (promotion engine, quarantine, lifecycle rules),
`zp-observation` (observer pipeline, reflector, receipt-backed observations),
`zp-learning` (episode recording, pattern detection),
`zp-skills` (skill registry and matching),
`zp-llm` (provider pool with risk-based routing)

**Compromise Plane (recovery and containment)**:
`zp-keys` (key rotation with parent co-signing),
`zp-anchor` (pluggable DLT abstraction for external chain verification),
`zp-mesh` (Reticulum-compatible sovereign transport),
`zp-introduction` (governed cross-node trust establishment)

**Cross-cutting**:
`zp-config` (unified configuration with provenance),
`zp-preflight` (installation readiness diagnostics)

### 1.2 Test Baseline

| Crate | Tests | Status |
|-------|-------|--------|
| zp-trust | 48 | All pass |
| zp-engine | 24 | All pass |
| zp-cli | 50 | All pass (ARTEMIS-verified) |
| zp-hardening-tests | 13 | All pass (Shannon regression) |
| Full workspace | ~700+ | Compiles clean (2 cosmetic warnings) |

### 1.3 Pentest Baseline

Shannon pentest (April 6-8, 2026) found 41 vulnerabilities:
6 truth falsification (Category A), 4 meaning corruption (Category B),
27 pathway compromise (Category C), 4 availability (Category D).

Post-pentest hardening cycle (relay 020-025) addressed all P0/P1
findings. Auth middleware is wired to the router. HMAC-SHA256 session
tokens with rate limiting. CSP fully compliant. 13/13 regression
tests pass.

**Open remediation items** (P2 and below):
- Command execution uses prefix allowlist (EXEC-02 structural fix
  incomplete — needs per-program arg validators)
- Path canonicalization not uniformly enforced
- Internal service zero-trust boundaries not formalized

---

## 2. Pathway Plane — Engineering Enforcement

*"Engineering secures the pathway."*

**Depth: Sprint-level.** Every item has a file path, a function
signature, and acceptance criteria.

### 2.1 Current State

The pathway plane received the most hardening work to date:

**Done:**
- Auth middleware wired to Axum router (`zp-server/src/lib.rs:955-969`)
- HMAC-SHA256 session tokens, per-IP rate limiting, TLS cookies
- Credential vault rewritten: tiered ontology (Providers/Tools/System/
  Ephemeral), VaultEntry::Ref for pointer-based sharing, BLAKE3 per-tier
  sub-keys (`zp-trust/src/vault.rs`)
- Zero plaintext on disk: .env files eliminated, vault is sole authority
  (`zp-cli/src/configure.rs` — commits 064d061 through 263f9c6)
- MVC/ConfigEngine dual-engine seam collapsed: `resolve_mvc_to_vault()`
  writes directly from capability resolution to vault
- Credential rotation verification: `run_rotate()` walks ref graph
- CSP compliant: all scripts vendored, no inline, no unsafe-eval
- Canon permission enforcement at startup

**Not done:**
- Command execution allowlist (EXEC-01/02 structural fix)
- Path canonicalization at all file operation boundaries
- Internal zero-trust between services
- Canonical serialization before signing
- Schema validation at every API boundary

### 2.2 Build Plan

#### P2-1: Command execution allowlist (Priority: CRITICAL)

Replace `BLOCKED_PATTERNS` denylist + `ALLOWED_CMD_PREFIXES` prefix
match with exact program allowlist and per-program argument validators.

**File:** `crates/zp-server/src/auth.rs`

**Current** (broken):
```rust
// Prefix allowlist — "ls " matches "ls ; rm -rf /"
fn check_command(cmd: &str) -> Result<(), String>
```

**Target:**
```rust
/// Validate a command against the program allowlist.
/// Each allowed program has its own argument validator.
/// Default deny — unlisted programs are rejected.
pub fn validate_command(cmd: &str) -> Result<ValidatedCommand, CommandError> {
    let argv = shell_words::split(cmd)
        .map_err(|e| CommandError::ParseFailed(e.to_string()))?;
    let (program, args) = argv.split_first()
        .ok_or(CommandError::Empty)?;

    match program.as_str() {
        "git" => validate_git_args(args),
        "ls" | "cat" | "head" | "tail" | "wc" | "file" | "tree"
            => validate_fs_read_args(args),
        "docker" => validate_docker_args(args),
        _ => Err(CommandError::ProgramNotAllowed(program.to_string())),
    }
}

/// A validated command ready for execution.
/// Constructed only by validate_command — cannot be forged.
pub struct ValidatedCommand {
    program: String,
    args: Vec<String>,
}

impl ValidatedCommand {
    /// Execute without sh -c. Argv-based, no shell interpretation.
    pub fn spawn(&self) -> io::Result<Child> {
        Command::new(&self.program)
            .args(&self.args)
            .env_clear()
            .spawn()
    }
}
```

**Argument validators:**
- `validate_git_args`: allowlist of subcommands (`status`, `log`,
  `diff`, `branch`, `remote`, `show`, `ls-files`, `rev-parse`).
  Reject all others.
- `validate_fs_read_args`: canonicalize every path argument, reject
  if outside the tool's working directory. Reject `..`, symlinks
  that escape boundary, `/etc`, `/Users`, `~/.zeropoint`.
- `validate_docker_args`: allowlist of subcommands (`ps`, `logs`,
  `inspect`). Reject `run`, `exec`, `build`, anything with `-v`
  or `--privileged`.

**Deps:** Add `shell-words` crate to zp-server/Cargo.toml.

**Tests (zp-hardening-tests):**
- Regression: all EXEC-01 PoCs blocked (`;`, `&&`, `|`, `$()`, `` ` ``)
- Regression: all EXEC-02 weaponizations blocked (`curl` exfil,
  `docker run`, `cargo install`, `npm install`, `cat ~/.zeropoint/`)
- Positive: allowed commands with valid args succeed
- Edge: empty input, whitespace-only, NUL bytes, overlong args

**Acceptance:** Shannon regression suite passes with zero EXEC findings.

#### P2-2: Path canonicalization boundary (Priority: HIGH)

All file operations must canonicalize paths and verify they fall within
permitted boundaries before any I/O.

**Files:**
- `crates/zp-server/src/lib.rs` (any handler accepting path params)
- `crates/zp-server/src/tool_chain.rs`
- `crates/zp-cli/src/configure.rs` (template reading)

**Implementation:**
```rust
/// Canonicalize a path and verify it falls within the allowed boundary.
/// Returns Err if the path escapes, contains symlink escapes, or is
/// otherwise unsafe.
pub fn safe_path(
    raw: &str,
    boundary: &Path,
) -> Result<PathBuf, PathError> {
    let canonical = std::fs::canonicalize(raw)
        .map_err(|e| PathError::ResolveFailed(raw.to_string(), e))?;
    if !canonical.starts_with(boundary) {
        return Err(PathError::EscapesBoundary {
            path: canonical,
            boundary: boundary.to_path_buf(),
        });
    }
    Ok(canonical)
}
```

Apply at every entry point that accepts a file path from external
input: HTTP params, WebSocket messages, CLI args. Internal paths
(vault storage, config loading) are trusted.

**Tests:**
- `../../etc/passwd` → rejected
- Symlink pointing outside boundary → rejected
- Valid relative path within boundary → canonicalized and accepted
- Unicode normalization attacks (e.g., `..%2f`) → rejected at parse

#### P2-3: Internal zero-trust boundaries (Priority: HIGH)

Every internal service boundary crossing requires a capability token.
This addresses SSRF-VULN-01/02 from the Shannon pentest.

**Current problem:** Internal HTTP calls between components (e.g.,
tool proxy → tool, onboard → configure) carry no authorization.
An SSRF into an internal endpoint gets full access.

**Design:**
```rust
/// A short-lived capability token for internal service calls.
/// Generated per-request, scoped to a specific action, signed
/// by the server's operator key.
pub struct InternalCapabilityToken {
    pub action: String,           // e.g., "tool:health:check"
    pub target: String,           // e.g., "pentagi"
    pub issued_at: u64,
    pub expires_at: u64,          // 30-second TTL
    pub nonce: [u8; 16],
    pub signature: Vec<u8>,       // Ed25519 by operator key
}
```

Internal endpoints validate the token before processing. Tokens are
not replayable (nonce + TTL). Tokens are not forwardable (action +
target scoping).

**Files:**
- New: `crates/zp-server/src/internal_auth.rs`
- Modified: every internal handler that accepts requests from other
  server components

**Decision gate:** Does this require the operator key to be loaded at
all times, or should we derive a separate internal signing key?
Recommendation: derive from operator key via BLAKE3 context
`"zeropoint internal auth v1"`.

#### P2-4: Schema validation at API boundaries (Priority: MEDIUM)

Replace loose JSON parsing with strict typed schemas at every HTTP
and WebSocket endpoint.

**Current problem:** Several endpoints accept `serde_json::Value`
and extract fields manually. Missing fields silently default.
Unexpected fields are ignored.

**Implementation:** Define request/response structs with
`#[serde(deny_unknown_fields)]` for every endpoint. Use
`axum::extract::Json<T>` where `T` is a strongly-typed request.
Reject malformed input at deserialization, before any business logic.

**Scope:** Audit all handlers in `zp-server/src/lib.rs` and
`zp-server/src/onboard/`. Estimate: ~30 endpoints need typed schemas.

#### P2-5: Canonical serialization before signing (Priority: MEDIUM)

Receipts and audit entries must be canonically serialized before
signing. Two structurally identical values must produce the same
signature regardless of field ordering in the JSON serializer.

**Current risk:** `serde_json` does not guarantee field ordering for
structs (though in practice it uses declaration order). HashMap
serialization is explicitly unordered.

**Implementation:** Use `serde_json::to_string` on a
`BTreeMap`-based canonical form, or adopt a deterministic serializer
like `ciborium` (CBOR with deterministic mode). Receipt's
`content_hash` already uses BLAKE3 — ensure the pre-hash bytes are
canonical.

**Files:** `crates/zp-receipt/src/hasher.rs`,
`crates/zp-audit/src/` (audit entry hashing)

#### P2-6: Wire run_rotate into CLI arg parser (Priority: LOW)

`run_rotate` exists as a library function in `configure.rs` but is
not yet a CLI subcommand.

**File:** `crates/zp-cli/src/main.rs`

**Implementation:** Add `Rotate` variant to the CLI subcommand enum
with `--provider` and `--field` args. Dispatch to
`configure::run_rotate(&vault, &provider, &field)`.

**Tests:** End-to-end: `zp configure rotate --provider anthropic
--field api_key` exits 0 when refs resolve, exits 1 when provider
missing.

---

## 3. Claim Plane — Cryptographic Proof

*"Cryptography secures the claim."*

**Depth: Interface-level.** Type signatures, validation rules, and
storage formats specified. Implementation follows existing patterns
in zp-receipt.

### 3.1 Current State

The claim plane is architecturally strong:

**Done:**
- `zp-receipt` defines 14 ReceiptType variants including typed claims:
  ObservationClaim, PolicyClaim, AuthorizationClaim,
  MemoryPromotionClaim, DelegationClaim, NarrativeSynthesisClaim,
  RevocationClaim, ReflectionClaim
- ClaimSemantics enum: AuthorshipProof, IntegrityAttestation,
  TruthAssertion, AuthorizationGrant
- Full builder pattern, Ed25519 signing, BLAKE3 content hashing
- Receipt chaining with ChainMetadata (prev_hash, chain_id, sequence)
- `zp-keys` provides Genesis → Operator → Agent hierarchy with
  certificate chain verification (6 invariants)
- `zp-audit` provides append-only hash-chained audit trail
- `zp-verify` provides receipt and chain verification utilities

**Not done:**
- Receipts are typed but not semantically validated — any ReceiptType
  can carry any content, no per-type validation rules enforced
- No supersession/revocation linkage between receipts
- No explicit expiry enforcement per claim type
- ClaimMetadata variants defined but not all wired into consumers

### 3.2 Build Plan

#### C3-1: Per-type receipt validation rules (Priority: HIGH)

Each ReceiptType should carry type-specific validation constraints
that are enforced at construction and verification time.

**Design:**
```rust
/// Validation rules enforced per receipt type.
pub trait ClaimValidation {
    /// Required fields that must be present in receipt content.
    fn required_fields(&self) -> &[&str];

    /// Maximum TTL before this claim type expires automatically.
    /// None = never expires.
    fn max_ttl(&self) -> Option<Duration>;

    /// Minimum ClaimSemantics required.
    /// e.g., MemoryPromotionClaim requires TruthAssertion.
    fn required_semantics(&self) -> ClaimSemantics;

    /// Whether this claim type requires human review before
    /// it can be used as evidence for further promotions.
    fn requires_human_review(&self) -> bool;
}
```

**Per-type rules:**

| Claim Type | Max TTL | Required Semantics | Human Review |
|------------|---------|-------------------|--------------|
| ObservationClaim | 24h | AuthorshipProof | No |
| PolicyClaim | None | IntegrityAttestation | No |
| AuthorizationClaim | 8h (session) | AuthorizationGrant | No |
| MemoryPromotionClaim | None | TruthAssertion | Stage-dependent |
| DelegationClaim | Configurable | AuthorizationGrant | Yes |
| NarrativeSynthesisClaim | None | TruthAssertion | Yes |
| RevocationClaim | None | IntegrityAttestation | No |
| ReflectionClaim | 7d | AuthorshipProof | No |

**File:** `crates/zp-receipt/src/validation.rs` (new)

**Integration:** `ReceiptBuilder::build()` calls
`self.receipt_type.validate(&self)` before signing. Invalid receipts
cannot be constructed.

#### C3-2: Receipt supersession and revocation linkage (Priority: HIGH)

Receipts should be able to reference prior receipts they supersede
or revoke. This is how credential rotation, memory quarantine, and
policy updates maintain causal coherence.

**Design:**
```rust
/// Added to Receipt struct.
pub struct Receipt {
    // ... existing fields ...

    /// Receipt IDs this receipt supersedes. The superseded receipts
    /// remain in the chain but are no longer the current authority.
    pub supersedes: Vec<ReceiptId>,

    /// Receipt IDs this receipt explicitly revokes. Revoked receipts
    /// are treated as void — any downstream claims that depend on
    /// them must be re-evaluated.
    pub revokes: Vec<ReceiptId>,
}
```

**Verification rule:** A receipt that has been revoked by a later
receipt in the same chain cannot be used as evidence for memory
promotion or delegation. `zp-verify` must check the revocation
index before accepting any receipt as valid.

**Revocation index:** In-memory index maintained by the audit store,
rebuilt from chain on startup:
```rust
pub struct RevocationIndex {
    /// receipt_id → revoking_receipt_id
    revoked: HashMap<ReceiptId, ReceiptId>,
}
```

**Files:**
- `crates/zp-receipt/src/types.rs` — add fields
- `crates/zp-verify/src/` — revocation-aware verification
- `crates/zp-audit/src/` — revocation index

#### C3-3: Typed claim emission from existing code paths (Priority: MEDIUM)

The claim types are defined but not all code paths emit the correct
typed receipts. Audit existing receipt emission points and ensure
each uses the appropriate ReceiptType.

**Audit scope:**
- Governance gate pipeline (`zp-pipeline`) — should emit PolicyClaim
- Capability grants — should emit AuthorizationClaim
- Memory promotion (`zp-memory`) — already emits MemoryPromotionClaim
- Observation pipeline (`zp-observation`) — already emits
  ObservationClaim
- Key delegation (`zp-keys`) — should emit DelegationClaim
- Credential rotation — should emit RevocationClaim for old +
  AuthorizationClaim for new

---

## 4. Meaning Plane — Semantic Governance

*"Architecture secures the meaning."*

**Depth: Interface-level.** Type system evolution, provenance tracking,
and the observed/interpreted/admitted distinction.

### 4.1 Current State

**Done:**
- `GovernanceEventType` has 35 variants covering phases 1-4
- `PolicyDecision` model: Allow/Block/Warn/Review/Sanitize
- `CapabilityGrant` with scope matching
- `DelegationChain` with 8 invariants
- `zp-observation` provides receipt-backed observations with priority
  classification (Completed/Low/Medium/High)
- `zp-memory` `MemoryStage` enum: Transient → Observed → Interpreted
  → Trusted → Remembered → IdentityBearing

**Not done:**
- No explicit provenance on GovernanceEvents (which entity created
  them, through what authority chain)
- CapabilityGrants don't track whether they were externally issued
  vs internally generated (SSRF self-issuance vector)
- The observed/interpreted/admitted distinction exists in zp-memory's
  MemoryStage but is not enforced in the governance event pipeline
- GovernanceEvent and MemoryStage are not yet bridged — events don't
  automatically flow into the memory lifecycle

### 4.2 Build Plan

#### M4-1: Provenance tracking on governance events (Priority: HIGH)

Every GovernanceEvent must carry a provenance chain that records how
it was created and under whose authority.

**Design:**
```rust
/// Provenance of a governance event — who created it, how, and
/// under what authority chain.
pub struct EventProvenance {
    /// The entity that directly created this event.
    pub creator: ActorId,

    /// How the event was created.
    pub origin: EventOrigin,

    /// The capability grant that authorized this event, if any.
    pub authorization: Option<ReceiptId>,

    /// The delegation chain backing the authorization.
    pub delegation_chain: Option<Vec<ReceiptId>>,
}

pub enum EventOrigin {
    /// Created by direct user action (CLI, API).
    UserAction,
    /// Created by the policy engine during evaluation.
    PolicyEvaluation,
    /// Created by an internal system process.
    SystemInternal,
    /// Created by an external service request.
    ExternalRequest { source_ip: Option<String> },
    /// Created by delegation from another event.
    Delegated { parent_event: EventId },
}
```

**Impact on SSRF:** With provenance, a capability grant created via
`EventOrigin::ExternalRequest` is distinguishable from one created
via `EventOrigin::PolicyEvaluation`. Self-SSRF grants would carry
`ExternalRequest` origin and can be rejected by policy.

**File:** `crates/zp-core/src/governance.rs`

#### M4-2: Bridge governance events to memory lifecycle (Priority: MEDIUM)

GovernanceEvents should optionally feed into the memory promotion
pipeline. Repeated patterns of governance decisions become
observations, which can be promoted through the memory lifecycle.

**Design:** The bridge is a listener on the governance event stream
that converts significant events into `zp-observation` inputs:

```rust
/// Convert a governance event into an observation candidate.
/// Returns None for routine events (health checks, etc.).
pub fn event_to_observation(
    event: &GovernanceEvent,
) -> Option<ObservationCandidate> {
    match event.event_type {
        // Policy violations → High priority observations
        GovernanceEventType::PolicyTierViolation => Some(high_priority(event)),
        GovernanceEventType::DelegationRejected => Some(high_priority(event)),

        // Reputation changes → Medium priority
        GovernanceEventType::ReputationComputed => Some(medium_priority(event)),

        // Routine operations → skip
        GovernanceEventType::GuardEvaluation => None,
        // ...
    }
}
```

**File:** New `crates/zp-observation/src/governance_bridge.rs`

**Decision gate:** Which GovernanceEventTypes are observation-worthy?
This is a policy question, not an engineering one. Default to
conservative (only violations and anomalies), let operators configure.

#### M4-3: CapabilityGrant self-issuance prevention (Priority: HIGH)

Capability grants issued from within the system (e.g., via SSRF) must
be distinguishable from grants issued through the legitimate governance
pipeline.

**Implementation:** Extend CapabilityGrant with an `issued_via` field
of type `EventProvenance`. The governance gate pipeline sets this
automatically. Any grant without provenance, or with provenance
showing `ExternalRequest` origin on an internal-only capability,
is rejected.

**File:** `crates/zp-core/src/governance.rs` (CapabilityGrant struct)

---

## 5. Cognition Plane — Machine Thought Lifecycle

*"Governance secures promotion."*

**Depth: Architecture-level.** The core crate (zp-memory) has real
implementations. What's needed is integration, policy wiring, and
the human review gate for higher promotions.

### 5.1 Current State

**Implemented in zp-memory:**
- `PromotionEngine`: full implementation with register, reinforce,
  promote (5-stage gate), get, get_by_stage, eligible_for_promotion
- `PromotionThresholds`: configurable confidence and reinforcement
  count requirements per stage
- `QuarantineStore`: quarantine, bulk quarantine by source, reinstate,
  is_quarantined. Generates receipts.
- `lifecycle`: apply_lifecycle_rules, is_expired, is_review_due,
  sweep_lifecycle, demotion_target, demote, reaffirm.
  Stage-specific expiry (Observed: 24h, Interpreted: 7d,
  Trusted+: never auto-expire)

**Implemented in zp-observation:**
- `CognitionPipeline`: should_observe, should_reflect, process outputs
- `observer`: system prompt, prompt builder, output parser
- `reflector`: merge/upgrade/downgrade/complete/drop actions
- `receipts`: observation receipt generation with chaining,
  source range verification

**Implemented in zp-receipt:**
- MemoryPromotionClaim, ObservationClaim, ReflectionClaim types
- ClaimSemantics::TruthAssertion required for promoted memory

**Not implemented:**
- Human review gate for Remembered → IdentityBearing promotion
- Integration between zp-observation outputs and zp-memory promotion
  engine (they exist in separate crates, not wired together)
- Cross-context memory merging with receipt requirements
- Narrative synthesis (NarrativeSynthesisClaim type exists, no
  synthesis engine)
- Expiry/review notification system (lifecycle can detect, but
  who acts on it?)

### 5.2 Build Plan

#### G5-1: Wire observation pipeline to promotion engine (Priority: HIGH)

The observation pipeline (zp-observation) produces observations.
The promotion engine (zp-memory) manages the lifecycle. They need
to be connected.

**Design:**
```rust
/// Bridge between observation output and memory promotion.
/// Called after the observation pipeline processes a batch.
pub fn ingest_observations(
    observations: &[Observation],
    promotion_engine: &mut PromotionEngine,
    receipt_chain: &mut ReceiptChain,
) -> Vec<PromotionResult> {
    observations.iter().map(|obs| {
        // Register as Transient memory
        let entry = promotion_engine.register_from_observation(obs);

        // If priority is High + confidence > threshold,
        // auto-promote to Observed
        if obs.priority >= ObservationPriority::High {
            promotion_engine.promote(
                &entry.id,
                MemoryStage::Observed,
                &observation_receipt_as_evidence(obs),
                receipt_chain,
            )
        } else {
            PromotionResult::Promoted(entry)
        }
    }).collect()
}
```

**File:** New integration module, likely in a shared crate or
in the server's runtime wiring.

**Decision gate:** Where does this integration live? Options:
a) In zp-memory (adds zp-observation dependency)
b) In zp-observation (adds zp-memory dependency)
c) In a new zp-cognition crate that depends on both
d) In zp-server runtime wiring (no new crate)

Recommendation: (d) for now. The server already depends on both
crates. A dedicated zp-cognition crate makes sense later when the
integration surface grows.

#### G5-2: Human review gate (Priority: HIGH)

Promotion from Trusted → Remembered and from Remembered →
IdentityBearing must require human review. The existing
`requires_human_review()` field on MemoryPromotionClaim supports
this; the review workflow needs implementation.

**Design:**
```rust
/// A pending promotion that requires human review.
pub struct PendingPromotion {
    pub memory_id: String,
    pub current_stage: MemoryStage,
    pub target_stage: MemoryStage,
    pub evidence: Vec<ReceiptId>,
    pub requested_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,  // 7 days
}

/// Human review decision.
pub enum ReviewDecision {
    /// Approve promotion. Generates MemoryPromotionClaim with
    /// ClaimSemantics::TruthAssertion.
    Approve,
    /// Reject promotion. Memory remains at current stage.
    /// Optionally demote or quarantine.
    Reject { reason: String, action: ReviewAction },
    /// Defer — keep in review queue, extend expiry.
    Defer,
}

pub enum ReviewAction {
    KeepAtCurrentStage,
    Demote(MemoryStage),
    Quarantine,
}
```

**Surface:** Initially CLI-only (`zp memory review`). Web dashboard
surface in Phase 4 per the original roadmap.

**File:** `crates/zp-memory/src/review.rs` (new)

#### G5-3: Cross-context memory merging (Priority: LOW)

When memories from different contexts (different tools, different
sessions, different agents in a mesh) are merged, the merge must
produce a receipt with evidence from both source contexts.

**Deferred until:** Multi-agent mesh operation is active. The
single-operator model doesn't produce cross-context merges yet.

#### G5-4: Narrative synthesis engine (Priority: LOW)

NarrativeSynthesisClaim type exists in zp-receipt. The engine
that produces narratives from promoted memories is not built.

**Deferred until:** The promotion pipeline (G5-1, G5-2) is
operational and producing Remembered-stage memories worth
synthesizing into identity-bearing narratives.

---

## 6. Compromise Plane — Recovery and Containment

*"Recovery secures legitimacy after compromise."*

**Depth: Architecture-level.** Primitives exist (key rotation,
quarantine, receipt chains). Design decisions needed for revocation
mechanics and reconstitution procedures.

### 6.1 Current State

**Done:**
- Key rotation: `zp keys rotate` implemented for operator and agent
  keys, with parent co-signing and rotation certificate persistence
  (`~/.zeropoint/keys/rotations.json`)
- BIP-39 mnemonic recovery: full pipeline from 24 words → Ed25519
  secret → verify against genesis cert → re-seal to OS credential store
- Credential vault rotation verification: `run_rotate()` walks ref
  graph, confirms all tool refs see current provider value
- QuarantineStore in zp-memory: quarantine, bulk quarantine by source,
  reinstate, is_quarantined
- Hash-chained audit trail: tamper-evident by construction
- Portable receipts: independently verifiable offline

**Not done:**
- Formal receipt revocation chain (designed in C3-2 above)
- Memory quarantine triggered by compromise detection (quarantine
  primitives exist, trigger logic doesn't)
- Narrative rollback (no narrative engine yet → G5-4)
- Reconstitution procedure from receipt chain after partial failure
- Blast radius scoping: no formal model for which trust relationships
  are invalidated when a specific key is compromised
- Downgrade resistance: no mechanism to prevent rollback to a prior
  (less restrictive) policy

### 6.2 Build Plan

#### R6-1: Blast radius model (Priority: HIGH)

When a key is compromised, the system must know exactly which trust
relationships, capability grants, and memories are affected.

**Design:**
```rust
/// Given a compromised key, compute the blast radius:
/// every entity whose trust chain passes through this key.
pub fn blast_radius(
    compromised_key: &PublicKey,
    audit_chain: &AuditChain,
    delegation_index: &DelegationIndex,
) -> BlastRadius {
    BlastRadius {
        /// Receipts signed by this key (directly affected).
        signed_receipts: find_receipts_signed_by(compromised_key, audit_chain),

        /// Delegation chains that include this key.
        affected_delegations: delegation_index.chains_through(compromised_key),

        /// Capability grants authorized through affected delegations.
        affected_grants: find_grants_through_delegations(
            &affected_delegations, audit_chain),

        /// Memories promoted using affected receipts as evidence.
        affected_memories: find_memories_with_evidence(
            &signed_receipts, promotion_engine),
    }
}
```

**Response actions per blast radius element:**
- Signed receipts → emit RevocationClaim for each
- Delegation chains → revoke the delegation, re-issue from parent
- Capability grants → revoke and re-grant through clean chain
- Memories → quarantine (using existing QuarantineStore), flag for
  re-evaluation after key rotation

**File:** New `crates/zp-keys/src/blast_radius.rs` or in zp-verify

#### R6-2: Compromise-triggered memory quarantine (Priority: MEDIUM)

Wire the blast radius model to the quarantine store. When a key
compromise is detected (via `zp keys rotate` or external report),
automatically quarantine all memories whose promotion evidence
includes receipts signed by the compromised key.

**Implementation:** After blast radius computation:
```rust
for memory_id in blast_radius.affected_memories {
    quarantine_store.quarantine(
        &memory_id,
        QuarantineReason::CompromisedEvidence {
            key: compromised_key.clone(),
            receipts: find_evidence_receipts(&memory_id),
        },
    )?;
}
```

Quarantined memories are excluded from the active memory set until
manually reinstated after review.

**Files:** Integration in `crates/zp-keys/src/rotation.rs` or
server runtime wiring.

#### R6-3: Receipt-based reconstitution (Priority: MEDIUM)

After a partial system failure (corrupted database, lost state),
reconstruct the current state by replaying the receipt chain.

**Design principle (from RECEIPT-DERIVED-STATE.md):**
```
state(t) = reduce(filter(C, t))
```

The receipt chain is the source of truth. The audit database, memory
store, and capability index are all projections that can be rebuilt.

**Implementation:**
```rust
/// Reconstruct system state from a receipt chain.
/// Used after data loss or corruption.
pub fn reconstitute(
    chain: &ReceiptChain,
    revocation_index: &RevocationIndex,
) -> ReconstitutedState {
    let mut state = ReconstitutedState::empty();

    for receipt in chain.iter_verified() {
        // Skip revoked receipts
        if revocation_index.is_revoked(&receipt.id) {
            continue;
        }

        match receipt.receipt_type {
            ReceiptType::AuthorizationClaim =>
                state.apply_authorization(receipt),
            ReceiptType::MemoryPromotionClaim =>
                state.apply_promotion(receipt),
            ReceiptType::RevocationClaim =>
                state.apply_revocation(receipt),
            ReceiptType::DelegationClaim =>
                state.apply_delegation(receipt),
            // ...
        }
    }

    state
}
```

**Decision gate:** How far back can we reconstitute? The full chain
from genesis? Or from the last checkpoint? Recommendation: support
both. Periodic checkpoints (signed snapshots of projected state)
allow fast recovery; full-chain replay is the fallback when
checkpoint integrity is in doubt.

#### R6-4: Downgrade resistance (Priority: LOW)

Prevent rollback to a prior, less restrictive policy version.

**Design:** Policy modules carry a monotonically increasing version
number. The policy engine refuses to load a module whose version is
lower than the currently active version. The version is part of the
signed module metadata and cannot be forged without the signing key.

**Deferred until:** Policy module hot-reload is production-ready.

---

## 7. Build Sequence

The build plan above contains ~18 items across five planes. Here's
the recommended execution order, organized into phases that align
with the existing ARCHITECTURE.md roadmap.

### Phase 2.5: Pathway Hardening (immediate — before any new features)

This is the doctrine's highest priority: "the pathway layer must be
hardened before any new capabilities are added."

| ID | Item | Priority | Est. |
|----|------|----------|------|
| P2-1 | Command execution allowlist | CRITICAL | 2-3 days |
| P2-2 | Path canonicalization | HIGH | 1-2 days |
| P2-3 | Internal zero-trust boundaries | HIGH | 3-4 days |
| P2-6 | Wire run_rotate into CLI | LOW | 0.5 day |

**Exit criteria:** Shannon regression suite re-run with zero findings.
ARTEMIS greenfield install + full pentest cycle.

### Phase 2.6: Claim Formalization

| ID | Item | Priority | Est. |
|----|------|----------|------|
| C3-1 | Per-type receipt validation | HIGH | 2-3 days |
| C3-2 | Receipt supersession/revocation | HIGH | 2-3 days |
| C3-3 | Typed claim emission audit | MEDIUM | 1-2 days |

**Exit criteria:** Every receipt in the system is typed, validated at
construction, and carries correct ClaimSemantics. Revocation index
operational.

### Phase 2.7: Meaning Layer Hardening

| ID | Item | Priority | Est. |
|----|------|----------|------|
| M4-1 | Event provenance tracking | HIGH | 2-3 days |
| M4-3 | CapabilityGrant self-issuance prevention | HIGH | 1 day |
| M4-2 | Governance→memory bridge | MEDIUM | 2 days |

**Exit criteria:** No capability grant can be issued without
provenance. SSRF self-grant vector closed.

### Phase 2.8: Pathway Polish

| ID | Item | Priority | Est. |
|----|------|----------|------|
| P2-4 | Schema validation at API boundaries | MEDIUM | 3-4 days |
| P2-5 | Canonical serialization before signing | MEDIUM | 1-2 days |

**Exit criteria:** Full API schema coverage. Deterministic signing.

### Phase 3: Cognition Integration (the "it's alive" milestone)

| ID | Item | Priority | Est. |
|----|------|----------|------|
| G5-1 | Wire observation→promotion pipeline | HIGH | 3-4 days |
| G5-2 | Human review gate | HIGH | 2-3 days |
| R6-1 | Blast radius model | HIGH | 2-3 days |
| R6-2 | Compromise-triggered quarantine | MEDIUM | 1-2 days |

**Exit criteria:** Observations flow through promotion. Human review
gate operational for high-stage promotions. Key compromise triggers
automatic quarantine of affected memories.

### Phase 3.5: Recovery Infrastructure

| ID | Item | Priority | Est. |
|----|------|----------|------|
| R6-3 | Receipt-based reconstitution | MEDIUM | 3-4 days |
| R6-4 | Downgrade resistance | LOW | 1 day |
| G5-3 | Cross-context memory merging | LOW | Deferred |
| G5-4 | Narrative synthesis engine | LOW | Deferred |

**Exit criteria:** System can reconstruct state from receipt chain
after partial failure. Policy downgrade rejected.

### Phases 4-5 (unchanged from ARCHITECTURE.md)

Phase 4 (Channels & Dashboard) and Phase 5 (Enterprise & Genesis)
proceed as originally planned, now building on the hardened pathway,
formalized claims, and operational cognition pipeline.

---

## 8. Decision Gates

These items require architectural decisions before engineering can
proceed. Each is called out in its section above; collected here
for reference.

1. **Internal auth key derivation** (P2-3): Derive internal signing
   key from operator key via BLAKE3 context, or use a separate key?
   Recommendation: derive. One key to manage, deterministic.

2. **Observation→memory integration location** (G5-1): New crate,
   or server runtime wiring? Recommendation: server wiring for now.

3. **Governance event observation policy** (M4-2): Which event types
   are observation-worthy? Recommendation: violations and anomalies
   only, operator-configurable.

4. **Reconstitution scope** (R6-3): Full chain replay vs. checkpoint
   + incremental? Recommendation: support both.

5. **Canonical serialization format** (P2-5): JSON with BTreeMap
   ordering vs. CBOR deterministic mode? Recommendation: JSON with
   BTreeMap for now (no new dependency), migrate to CBOR if cross-
   language verification becomes necessary.

---

## 9. The ARTEMIS Build Fix Backlog

ARTEMIS identified 4 compilation errors in the current bundle that
are patched on ARTEMIS's end but not yet committed to main:

| Fix | File | Status |
|-----|------|--------|
| Add `debug` to tracing import | zp-server/src/lib.rs | Fixed at source |
| Add `warn` to tracing import | zp-cli/src/configure.rs | Fixed at source |
| Remove `_` prefix from `vault_path` | zp-cli/src/onboard.rs | Fixed at source |
| `&CredentialVault` → `&mut` | zp-cli/src/onboard.rs | Fixed at source |

All four are fixed in the working tree as of this writing. Next
commit will include them so ARTEMIS's bundle compiles clean.

---

## 10. The Invariants

From the doctrine memo, restated here as engineering constraints.
Every item in this spec must preserve all six:

1. **Nothing becomes durable truth merely because a model inferred it.**
   Enforced by: MemoryStage promotion gates, human review for
   Remembered+, TruthAssertion semantics required.

2. **Nothing becomes trusted merely because it came from inside.**
   Enforced by: EventProvenance on all governance events, internal
   capability tokens, zero-trust boundaries.

3. **Nothing becomes authorized merely because it is signed.**
   Enforced by: ClaimSemantics distinction (AuthorshipProof ≠
   TruthAssertion), per-type validation rules.

4. **Nothing becomes harmless merely because it is elegant.**
   Enforced by: Pathway hardening before new features, Shannon
   regression suite, ARTEMIS functional testing.

5. **Nothing becomes unrecoverable merely because it was compromised.**
   Enforced by: Blast radius model, quarantine, receipt-based
   reconstitution, BIP-39 recovery.

6. **Nothing becomes enforceable merely because it is written in policy.**
   Enforced by: This spec. Every design gets a file path, a test,
   and acceptance criteria. If it isn't wired, it isn't real.

---

*Cryptography secures the claim. Engineering secures the pathway.
Architecture secures the meaning. Governance secures promotion.
Receipts secure continuity. Recovery secures legitimacy after
compromise.*
