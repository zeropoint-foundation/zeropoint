# ZeroPoint Design Patterns

## Engineering Invariants for a Governed Compute Platform

> **Audience:** Anyone reading, reviewing, or contributing to ZeroPoint's Rust codebase. This document is prescriptive, not descriptive — code that violates these patterns should be treated as a bug.

**Purpose:** ZeroPoint's security properties emerge from a small number of patterns applied consistently across every crate. This document names them, explains why each exists, and points to the canonical implementation so you can verify the pattern is real, not aspirational.

---

## 1. Type-Level Enforcement

**Principle:** If a security property can be expressed as a type, it must be. Runtime checks are defense-in-depth, not the primary gate.

The `ValidatedCommand` type in `zp-server/src/auth.rs` cannot be constructed except by calling `validate_command()`. This function runs the full allowlist check, POSIX tokenization via `shlex::split`, and per-program argument validation. Once you hold a `ValidatedCommand`, the compiler guarantees it passed every check. You cannot forge one, skip validation, or accidentally construct one from raw input.

```rust
// The only public constructor runs the full validation pipeline
pub fn validate_command(cmd: &str) -> Result<ValidatedCommand, CommandError>

// ValidatedCommand::spawn() is the only way to execute — and it
// requires a validated CWD path. Two type-level gates, composed.
validated_cmd.spawn(&resolved_cwd)
```

The same pattern appears in `ReceiptBuilder::try_finalize()`: a `Receipt` produced through `try_finalize()` is guaranteed to satisfy its type's validation rules — correct semantics, required metadata present, TTL within bounds. The type system encodes the invariant.

**Where to look:** `crates/zp-server/src/auth.rs` (ValidatedCommand), `crates/zp-receipt/src/builder.rs` (try_finalize), `crates/zp-receipt/src/validation.rs` (TypeRules).

**The test:** If someone can construct the protected type without going through the validation path, the pattern is broken.

---

## 2. Derived Keys, Never Exposed Originals

**Principle:** High-value keys are never used directly for routine operations. Derived keys are produced via BLAKE3 keyed derivation with a unique context string, creating cryptographic independence.

The operator's Ed25519 signing key is the root of trust for a ZeroPoint instance. Using it directly for every internal service call would create a massive blast radius if any single call site leaked the key. Instead, the internal auth system derives a separate HMAC key:

```rust
let derived = blake3::derive_key("zeropoint internal auth v1", signing_key_bytes);
```

This derived key is cryptographically independent — compromising it does not reveal the operator key. The context string `"zeropoint internal auth v1"` ensures the derivation is domain-separated: the same signing key bytes with a different context produce a completely different derived key.

The same pattern governs the credential vault. Each tier (Providers, Tools, System, Ephemeral) derives its own encryption key from the genesis key via BLAKE3 with a tier-specific context. Compromising the Tools tier key reveals nothing about the Providers tier.

**Where to look:** `crates/zp-server/src/internal_auth.rs` (InternalAuthority::new), `crates/zp-keys/src/vault.rs` (per-tier derivation).

**The test:** Grep the codebase for direct use of `signing_key` or `genesis_key` outside of derivation functions. Any direct use in a hot path is a violation.

---

## 3. Scoped, Short-Lived, Non-Replayable Tokens

**Principle:** No ambient authority. Every internal service boundary crossing requires a capability token that is scoped to a specific action and target, expires quickly, and cannot be replayed.

The `InternalCapabilityToken` carries four constraints simultaneously:

```rust
pub struct InternalCapabilityToken {
    pub action: String,      // What it authorizes: "verify:tier1", "verify:tier2"
    pub target: String,      // Which resource: tool name
    pub expires_at: u64,     // 30-second TTL
    pub nonce: String,       // Random, tracked for replay prevention
    pub signature: String,   // BLAKE3 keyed hash proving authenticity
}
```

Verification checks all five properties in order: signature (catches forgery), expiration (catches stolen tokens), action match (catches scope escalation), target match (catches lateral movement), nonce uniqueness (catches replay). A token that passes all five checks is consumed — it cannot be used again.

This pattern exists because the Shannon pentest found SSRF vectors (SSRF-VULN-01/02) where verification endpoints could be probed without authentication. Every internal call now carries proof of authorization that is specific to exactly what it needs to do.

**Where to look:** `crates/zp-server/src/internal_auth.rs` (issue/verify), `crates/zp-server/src/onboard/verify.rs` (token injection into probe headers).

**The test:** Remove the internal auth parameter from `verify_tool_capabilities` and confirm the Shannon SSRF regression tests fail.

---

## 4. Centralized Validation, Distributed Use

**Principle:** Security-critical logic exists in exactly one place. Every call site uses it. There is no "local version" of path validation or command checking.

`safe_path()` in `auth.rs` is the single function that canonicalizes paths, checks boundary containment, and rejects system paths. It is called from `exec_ws.rs` for CWD validation, from handler functions for log paths, and from preflight for tool paths. The function is 30 lines. It is the only place in the codebase that calls `std::fs::canonicalize` on user-provided paths.

```rust
pub fn safe_path(raw: &str, boundary: &Path) -> Result<PathBuf, PathError>
```

Before this pattern was applied, path validation was scattered across five files with subtly different logic. The Shannon pentest found traversal vectors in three of them. Centralizing created one function to audit, one function to test, and one function to get right.

The same pattern applies to `validate_command()` — there is no other place in the codebase that decides whether a command is allowed to execute.

**Where to look:** `crates/zp-server/src/auth.rs` (safe_path, validate_command), call sites in `exec_ws.rs`, `lib.rs`.

**The test:** Grep for `canonicalize`, `shlex::split`, or manual path traversal checks outside of `auth.rs`. Any hit is a pattern violation.

---

## 5. Hash-Then-Sign, Canonical Serialization

**Principle:** The content hash is computed over a deterministic representation of the receipt body before any signature is applied. The signature covers the hash. Verification checks both independently.

The `canonical_hash` function in `hasher.rs` explicitly enumerates every field in a `serde_json::json!()` macro rather than serializing the struct. This means:

1. Field ordering is deterministic (JSON object keys are enumerated in code order)
2. We control exactly what is included — `content_hash`, `signature`, and `signer_public_key` are excluded because they are computed after the body is finalized
3. DateTime values are formatted with explicit precision (`to_rfc3339_opts(Millis, true)`) so the same timestamp always produces the same string

```rust
let hash_input = serde_json::json!({
    "id": receipt.id,
    "version": receipt.version,
    "receipt_type": receipt.receipt_type,
    // ... every field explicitly listed ...
    "supersedes": receipt.supersedes,
    "revokes": receipt.revokes,
    // content_hash, signature, signer_public_key deliberately absent
});

let canonical = serde_json::to_string(&hash_input).unwrap_or_default();
blake3::hash(canonical.as_bytes()).to_hex().to_string()
```

Verification is two independent checks: (1) recompute the hash from the body and compare to `content_hash`, (2) verify the Ed25519 signature over `content_hash`. A receipt with a valid signature but tampered body fails check 1. A receipt with a valid body but forged signature fails check 2.

**Where to look:** `crates/zp-receipt/src/hasher.rs` (canonical_hash), `crates/zp-receipt/src/types.rs` (verify_hash, verify_signature).

**The test:** Add a new field to `Receipt` and forget to add it to `canonical_hash`. The `test_hash_changes_with_content` test should catch it — but also: any new field that isn't in the canonical hash is invisible to integrity verification, which is a security bug.

---

## 6. Forward and Backward References for Causal Coherence

**Principle:** When one receipt supersedes or revokes another, both the new receipt and the old receipt carry references. This allows chain traversal in either direction and makes the causal relationship explicit in both records.

A revocation creates references in both directions:

```rust
// On the OLD receipt (backward reference):
pub superseded_by: Option<String>,  // "I was replaced by this receipt"
pub revoked_at: Option<DateTime>,   // "I was voided at this time"

// On the NEW receipt (forward reference):
pub supersedes: Vec<String>,        // "I replace these receipts"
pub revokes: Vec<String>,           // "I void these receipts"
```

The `revoke()` method on `Receipt` sets both simultaneously — it marks the old receipt's `revoked_at` and builds a new `RevocationClaim` receipt with the old ID in its `revokes` vector. You cannot revoke a receipt without creating the forward reference.

The `RevocationIndex` in `zp-audit` materializes the forward references into an O(1) lookup: given any receipt ID, you can instantly determine whether it has been revoked or superseded and by whom. The index is rebuilt from the chain at startup and updated incrementally as new receipts arrive.

**Where to look:** `crates/zp-receipt/src/types.rs` (Receipt fields, revoke method), `crates/zp-audit/src/revocation.rs` (RevocationIndex).

**The test:** Revoke a receipt and verify that both the old receipt's `revoked_at` is set AND the new receipt's `revokes` vector contains the old ID. If either is missing, the causal link is broken.

---

## 7. Backward Compatibility with Progressive Strictness

**Principle:** New validation is introduced as opt-in strict mode alongside the existing lenient path. Existing code continues to work. New code is expected to use the strict path. The lenient path warns loudly.

`ReceiptBuilder` has two finalization methods:

```rust
// Strict: validates per-type rules, returns Result
pub fn try_finalize(self) -> Result<Receipt, ValidationError>

// Lenient: validates and warns, always returns Receipt
pub fn finalize(self) -> Receipt
```

Both call the same validation logic. `finalize()` logs a warning on failure but produces the receipt anyway. `try_finalize()` returns `Err`. Existing call sites that use `finalize()` are not broken by the introduction of validation — they get warnings in their logs that flag receipts that would fail strict validation. New code paths are expected to use `try_finalize()`.

This same pattern was used during P2-1: `check_command()` was preserved as a backward-compatible wrapper around `validate_command()`, mapping the new error types back to the old boolean return. Call sites were migrated incrementally.

**Where to look:** `crates/zp-receipt/src/builder.rs` (finalize vs try_finalize), `crates/zp-server/src/auth.rs` (check_command wrapping validate_command).

**The test:** Call `finalize()` with deliberately wrong semantics (e.g., `AuthorshipProof` on a `PolicyClaim`). Verify a warning is emitted but the receipt is still produced. Then call `try_finalize()` with the same input and verify it returns `Err(ValidationError::SemanticsRequired)`.

---

## 8. Epistemic Semantics on Claims

**Principle:** Every signed receipt carries an explicit statement of what the signature means. "I made this" is different from "I vouch for this" is different from "I assert this is true" is different from "I grant this authority."

The four levels form a partial order:

| Semantic | Meaning | Strength |
|----------|---------|----------|
| `AuthorshipProof` | "I produced this artifact" | 1 |
| `IntegrityAttestation` | "I verified this is correct" | 2 |
| `TruthAssertion` | "I assert this is true" | 3 |
| `AuthorizationGrant` | "I authorize this action" | 3 |

`TruthAssertion` and `AuthorizationGrant` are peers at the same strength — they don't satisfy each other, but both satisfy `IntegrityAttestation` and `AuthorshipProof`. A stronger semantic always satisfies a weaker requirement.

Each `ReceiptType` has a required minimum semantic. A `PolicyClaim` requires at least `IntegrityAttestation` — the signer must vouch for the policy evaluation, not merely claim authorship. A `MemoryPromotionClaim` requires `TruthAssertion` — promoting a memory to a higher confidence stage is a truth claim about the world.

**Where to look:** `crates/zp-receipt/src/validation.rs` (semantics_strength, semantics_satisfies, rules_for), `crates/zp-receipt/src/types.rs` (ClaimSemantics enum).

**The test:** Try to create a `PolicyClaim` with `AuthorshipProof` semantics via `try_finalize()`. It must fail with `SemanticsRequired`. Then try with `IntegrityAttestation` — it must succeed.

---

## 9. Receipt Emissions Match Their Semantic Role

**Principle:** The ReceiptType of an emission must match what is actually happening. A policy decision emits a `PolicyClaim`, not an `Execution` receipt. An observation emits an `ObservationClaim`, not a generic receipt. Getting this wrong means the receipt chain lies about what happened.

This was the subject of the C3-3 audit. The governance guard in `zp-cli/src/guard.rs` was emitting `Receipt::execution()` for what was clearly a policy allow/deny decision. The fix:

```rust
// Before (wrong): records a policy decision as if it were code execution
Receipt::execution("zp-guard")

// After (correct): records a policy decision as a policy claim
Receipt::policy_claim("zp-guard")
    .claim_semantics(ClaimSemantics::IntegrityAttestation)
    .claim_metadata(ClaimMetadata::Policy {
        rule_id: "zp-guard-embedded-v2".to_string(),
        principle: None,
        satisfied: result.allowed,
        rationale: result.reason.clone(),
    })
```

The receipt type determines what the `RevocationIndex` and reconstitution engine do with the receipt. A revoked `PolicyClaim` invalidates the policy decision. A revoked `Execution` receipt means the execution is voided. If a policy decision is recorded as an execution, revoking it has the wrong downstream effect.

**Where to look:** `crates/zp-cli/src/guard.rs` (PolicyClaim emission), `crates/zp-pipeline/src/pipeline.rs` (PolicyClaim at governance gate, Execution for tool calls), `crates/zp-memory/src/promotion.rs` (MemoryPromotionClaim), `crates/zp-observation/src/receipts.rs` (ObservationClaim, ReflectionClaim).

**The test:** For any receipt emission, ask: "What is the signer asserting?" If the answer is "this policy was evaluated," the type must be `PolicyClaim`. If the answer is "this code ran," the type must be `Execution`. If there is any doubt, the type is wrong.

---

## 10. Defense in Depth, Not Defense Instead Of

**Principle:** Multiple independent security layers exist for the same threat. The primary layer is the type-level or architectural enforcement. The secondary layer is a runtime check that catches anything that somehow bypasses the primary. Tests verify the outcome, not which layer caught it.

`BLOCKED_PATTERNS` in `auth.rs` is a regex-based blocklist that rejects known-dangerous command patterns. It exists alongside the program-level allowlist (`validate_command`). The allowlist is the real security boundary — only explicitly permitted programs can execute. The blocklist catches edge cases where a permitted program could be used dangerously (e.g., `curl` used for SSRF).

The tests use `.is_err()` rather than matching specific error variants:

```rust
// Correct: we don't care which layer caught it
assert!(validate_command("curl http://evil.com").is_err());

// Wrong: brittle coupling to implementation order
assert!(matches!(
    validate_command("curl http://evil.com"),
    Err(CommandError::ProgramNotAllowed(_))
));
```

If the blocklist fires before the allowlist, the command is still rejected. The security property holds. The test should verify the property, not the mechanism.

**Where to look:** `crates/zp-server/src/auth.rs` (BLOCKED_PATTERNS alongside validate_command), test functions using `.is_err()`.

**The test:** Disable BLOCKED_PATTERNS and verify that `validate_command` still rejects the same inputs via the allowlist. Then re-enable and verify both layers are active. The union of rejections should be the same or larger.

---

## 11. Pruning Over Unbounded Growth

**Principle:** When an in-memory cache has no natural eviction mechanism, use a simple size-based clear rather than per-entry expiration. This prevents memory exhaustion while maintaining correctness.

The nonce cache in `InternalAuthority` tracks recently-seen nonces to prevent replay attacks. Nonces are random 128-bit values — there's no natural ordering or expiration to use for cleanup. The solution is a hard cap:

```rust
if seen.len() >= MAX_NONCE_CACHE {
    seen.clear();  // Drop everything and start fresh
}
```

This is safe because the 30-second TTL on tokens means any nonce older than 30 seconds is already expired. By the time the cache reaches 10,000 entries at normal operating volume, the oldest entries are far past their window. Clearing the entire set is an O(1) operation that cannot cause a memory leak.

The alternative — per-entry expiration with timestamp tracking — adds complexity, requires a sorted data structure, and introduces a background cleanup task. All for a cache where staleness is harmless (an expired nonce that gets removed from the cache and then replayed will fail the TTL check anyway).

**Where to look:** `crates/zp-server/src/internal_auth.rs` (verify method, nonce cache pruning).

**The test:** Issue and verify 10,001 tokens. The 10,001st should succeed (cache was pruned, not rejected). Then immediately replay a token from before the pruning — it should fail on TTL, not on nonce check.

---

## 12. Dual Systems: Audit Chain and Receipt Chain

**Principle:** The operational log and the trust evidence are separate systems with different properties. Conflating them weakens both.

The **audit chain** (`zp-audit`) is a hash-chained append-only SQLite database. It records operational events: tool launched, preflight passed, configuration changed. Entries are lightweight, high-volume, and local. The chain is verified by hash linkage — each entry includes the hash of the previous entry.

The **receipt chain** (`zp-receipt`) produces portable, typed, cryptographically signed receipts. Each receipt carries epistemic semantics (what the signature means), type-specific metadata, and can be verified offline by anyone with the signer's public key. Receipts are the evidence layer for trust decisions.

They serve different consumers: the audit chain is read by the cockpit for operational status. Receipts are consumed by the reconstitution engine, the revocation index, and external verifiers.

A common mistake is to emit an audit entry when a receipt is needed, or vice versa. The rule: if the event needs to be verified by an external party or used as evidence for a trust decision, it needs a receipt. If it's operational telemetry for the local instance, an audit entry is sufficient. Some events need both — the pipeline emits both an audit entry and a PolicyClaim receipt for governance gate decisions.

**Where to look:** `crates/zp-server/src/tool_chain.rs` (audit chain emissions), `crates/zp-pipeline/src/pipeline.rs` (both systems used in the same function), `crates/zp-audit/src/store.rs` (AuditStore), `crates/zp-receipt/src/builder.rs` (ReceiptBuilder).

**The test:** Ask of any emission: "Does an external verifier need to see this?" If yes, it must be a typed receipt. "Does the local cockpit need to see this?" If yes, it must be an audit entry. If both, emit both.

---

## Summary Table

| # | Pattern | Primary Mechanism | Canonical File |
|---|---------|-------------------|----------------|
| 1 | Type-Level Enforcement | Unconstructable types | `auth.rs`, `builder.rs` |
| 2 | Derived Keys | BLAKE3 context derivation | `internal_auth.rs` |
| 3 | Scoped Tokens | Action + target + TTL + nonce | `internal_auth.rs` |
| 4 | Centralized Validation | Single function, many call sites | `auth.rs` |
| 5 | Hash-Then-Sign | Canonical JSON before hash | `hasher.rs` |
| 6 | Bidirectional References | Forward + backward on revocation | `types.rs`, `revocation.rs` |
| 7 | Progressive Strictness | Warn path + strict path | `builder.rs` |
| 8 | Epistemic Semantics | Strength-ordered claim types | `validation.rs` |
| 9 | Semantic Receipt Types | Type matches role | `guard.rs`, `pipeline.rs` |
| 10 | Defense in Depth | Blocklist behind allowlist | `auth.rs` |
| 11 | Pruning Over Growth | Size-cap with full clear | `internal_auth.rs` |
| 12 | Dual Systems | Audit chain vs receipt chain | `tool_chain.rs`, `builder.rs` |

---

## Adding a New Pattern

If you find yourself applying a security technique in more than one crate, it probably belongs in this document. The bar for inclusion: the pattern must be (1) consistently applied across the codebase, (2) load-bearing for a security property, and (3) expressible as a test that would catch violations.

Write the pattern, name the canonical implementation, and write the test. Then add it here.
