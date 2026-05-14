# The Singular Sovereign Root

*Drafted 2026-05-14. Folded into `ARCHITECTURE-2026-05.md` as section II.21
by commits 7f6397b + eb1975f + aba2b26 + 7a9d30d (Task #152, 2026-05-14).
This file is the extended argument; the architecture doc contains the summary
with implementation references. Triggered by the #150 walk-through: three
independent fixes were required to bring `zp configure exec` from 5–9 passkey
prompts down to 1, because three different code paths each loaded Genesis (or
genesis-derived material) from the credential store independently.*

## The principle

There is exactly **one sovereign root** in any ZeroPoint process:
Genesis. Every other piece of sensitive material in the process is
either:

1. **Derived from Genesis in memory** (e.g., the vault master key is
   `BLAKE3(genesis, "zp-credential-vault-v1")`; the audit signer seed
   is `derive_audit_signer_seed(genesis)`), or
2. **Stored in the vault** and decrypted on read using the vault master
   key from (1).

There is no third category. No secret in the substrate is independently
stored in the credential store with its own biometric gate. The
credential store holds Genesis (once, biometric-gated). Everything else
flows from there, in memory, within the process's lifetime.

This means: **one operator authentication ceremony per process
lifetime.** One Touch ID. One YubiKey tap. One M-of-N quorum
confirmation. Whatever sovereignty the operator has chosen, it
unlocks Genesis, and Genesis unlocks everything else.

## Why this is load-bearing

The current substrate had drifted away from this principle without
anyone noticing. Three different code paths — vault key derivation,
launch-receipt emission, and server-side audit-signer initialization —
each loaded Genesis (or treated something genesis-derived as if it
were a sovereign root) through the credential store. None of them
were strictly wrong; each was reasonable in isolation. Composed, they
produced 5–9 biometric prompts for one operator action.

The user-facing failure mode is obvious (annoying re-prompts). The
structural failure modes are worse:

- **Multi-quorum sovereignty is unbounded.** When 2-of-3 Trezors or
  1 Trezor + 1 YubiKey is the sovereignty model (per CLAUDE.md's
  "Architecture Direction: Multi-Signing / Quorum Sovereignty"),
  each independent credential-store read becomes M ceremonies, not
  one. The friction multiplies linearly with device count when the
  architecture allows it.
- **Threat-model surface is larger.** N independent secrets each
  with their own freshness, lifetime, and access semantics is a
  much larger reasoning surface than one root + derivation. Memory
  exposure, crash dumps, swap policy, zeroization — all easier to
  bound when there is one thing to protect.
- **Provider divergence is silent.** A new sovereignty provider
  (login_password, file_based, future hardware-wallet impls) that
  stores its own derived material in the credential store passes
  code review individually. The cumulative violation only shows up
  as accumulated friction once enough providers exist.
- **Audit trail authority is weaker.** If the audit signer can be
  loaded independently of Genesis, then in principle the audit chain
  can be signed by a key that the operator did not just authenticate
  for. The chain "owned by the operator" claim degrades.

By contrast, when Genesis is the single root and everything else is
derived, the chain has structural integrity: every signature in the
chain traces to one act of operator authentication. The chain says
what happened *and* who said it happened, with cryptographic
authority over both.

## What the code looks like after this lands

A single canonical loader:

```rust
// crates/zp-keys/src/sovereignty/mod.rs

/// Load the Genesis secret for this process, prompting the operator
/// for sovereignty authentication if needed. Cached process-scoped;
/// exactly one ceremony per process lifetime.
pub fn load_sovereign_root() -> Result<&'static [u8; 32], KeyError> {
    static CACHED: OnceLock<Result<[u8; 32], String>> = OnceLock::new();
    CACHED
        .get_or_init(|| load_uncached_via_provider().map_err(|e| e.to_string()))
        .as_ref()
        .map_err(|msg| KeyError::CredentialStore(msg.clone()))
        .map(|s| s)
}
```

Everything else in the substrate consumes this — vault key derivation,
audit signer seed, mesh identity, agent certificates, future verb
signatures. No direct `keyring::Entry::*` reads, no direct
`SecItemCopyMatching`, no direct hardware-wallet APDU calls outside
the sovereignty/ module. The contract is singular; the implementations
(Touch ID, YubiKey, Trezor, file-based, multi-quorum) are plural but
all funnel through the same consumer-facing surface.

A new discipline pin enforces it:

```
discipline: singular_sovereign_root

  Direct reads of system credential stores are forbidden outside
  crates/zp-keys/src/sovereignty/. All consumers must use
  zp_keys::sovereignty::load_sovereign_root() (or its derived
  helpers like vault_key, audit_signer_seed). Violations:

    - keyring::Entry::* calls outside sovereignty/
    - SecItemCopyMatching outside sovereignty/touchid.rs
    - direct hardware-wallet APDU calls outside sovereignty/hardware/
    - bioutil / fprintd-verify outside their respective provider modules

  Enforcement: zp-discipline AST scan, CI-failing.
```

And an integration test pins the behavior:

```rust
#[test]
fn full_restart_invokes_provider_at_most_once() {
    let mock_provider = MockBiometric::new();
    // simulate zp-dev.sh restart + zp configure exec
    run_full_cycle_under_mock(&mock_provider);
    assert_eq!(mock_provider.invocation_count(), 1);
}
```

## Connection to existing architecture

This is the same shape as Architecture II.0 (contracts singular,
implementations plural) applied to credential loading specifically.
The verb set, the audit signer, the canonical JSON helper, path
resolution — all of these went through the same arc:

1. Multiple call sites independently doing the same thing
2. Realization that the divergence has cost
3. One canonical helper introduced
4. Discipline pin to prevent regression

`singular_sovereign_root` is the credential-store edition of that
pattern. The Tier 1 work (Seam 5 verify_signature, Seam 17 canonical
JSON, Seam 19 path resolution) is the precedent — every one of those
was a structural cleanup of the same shape, with a discipline pin
landing alongside the refactor.

The four design principles from `docs/ARCHITECTURE-2026-04.md`
section V½ all bear on this:

- **Signing is gravity** — the audit signer must trace to one act of
  operator authentication; if it can be loaded independently of
  Genesis, the gravity is weaker
- **Identity is a key, not a location** — Genesis is the identity;
  derived keys are not separate identities, they are projections of
  the one identity, and treating them as separate identities (with
  separate credential-store entries) violates the principle
- **There is no center** — but inside a single process, there IS a
  center for that process's authority: Genesis. Loading anything
  else from outside the process boundary (credential store) is
  centralization without singularity
- **Every bit counts** — N redundant credential-store reads is the
  exact failure mode this principle was meant to catch

## Sequencing

In dependency order:

1. **Audit.** Enumerate every direct credential-store call site
   across the workspace. Categorize: "loads Genesis," "loads
   genesis-derived secret independently," "loads operator/mesh/agent
   identity," "other." This is a sweep, not a refactor — the goal
   is the catalog.
2. **Refactor.** Collapse each violating call site into either
   `load_sovereign_root()` + in-memory derivation, or
   `vault.retrieve(key)` after the vault is opened. No new abstractions;
   use what's already there.
3. **Discipline pin.** Land `singular_sovereign_root` in zp-discipline
   alongside the refactor.
4. **Integration test.** Mock the biometric layer; assert call count
   == 1 for the full `zp-dev.sh` + `zp configure exec` cycle.
5. **Fold this doc** into `ARCHITECTURE-2026-05.md` as section II.21.

## Out of scope

- Cross-process secret sharing (a separate, much harder problem;
  process-scoped singularity is the right primitive before any
  cross-process work is contemplated)
- Long-lived REPL / daemon contexts (TTL-based eviction is a future
  problem; for short-lived CLI invocations, process lifetime IS the
  TTL)
- The quorum-sovereignty implementation (already in CLAUDE.md as a
  forward direction; this principle is what makes it tractable, not
  a substitute for it)
- The forensic question of what to do about already-stored independent
  credential-store entries from previous versions (migration concern;
  separate task once the new path is in place)

## Open questions

- **Should `load_sovereign_root()` return `&'static [u8; 32]` or
  `Zeroizing<[u8; 32]>`?** The OnceLock can't zeroize on drop since
  it lives for process lifetime. References to a static are simpler
  but mean the secret can't be wiped before exit. `mlockall()` to
  prevent swap exposure is a separate mitigation.
- **What happens when the operator's sovereignty configuration
  changes mid-process?** (e.g., they enroll a new Trezor while the
  CLI is running). Probably: the cached secret remains valid for the
  process's lifetime; new enrollment takes effect on next invocation.
  Worth documenting explicitly.
- **Multi-quorum's interaction with caching.** If 2-of-3 devices
  confirmed Genesis at process start, does that quorum confirmation
  also cache, or does each high-stakes operation re-confirm? The
  default (cache for process lifetime) is permissive; a future
  per-operation re-confirmation mode is possible. Punt for now;
  document the question.

## Refs

- `docs/handoffs/vault-session-scoped-reads-design-2026-05.md` —
  the three fixes that triggered this principle
- `docs/ARCHITECTURE-2026-04.md` § V½ — the four design principles
- `docs/ARCHITECTURE-2026-05.md` § II.0 — contracts singular,
  implementations plural (the parent principle)
- CLAUDE.md → Architecture Direction → Multi-Signing / Quorum
  Sovereignty — the direction this principle protects
- Tier 1 work, Seams 5/17/19 — precedent for "one canonical
  helper + discipline pin" refactors
- Task #91 — load-bearing-honest hardening pass this belongs to
- Task #150 — the surfacing event
