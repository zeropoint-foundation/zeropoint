# Vault-Key Sovereignty Composition — Structural Finding

**Document type:** Tier 2 canonical elaboration + structural finding record.
**Elaborates:** KEEL §II.1 (cryptographic primitives), §II.5 (sovereign identity), Part XI (Genesis and rotation). Cross-cites CLAUDE.md workflow heuristic *Singular sovereign root*.
**Date:** 2026-07-18. Finding surfaced during APOLLO readiness audit for the observer-windows investigation. Scope widened same day after empirical `zp emit` test confirmed the drift extends beyond vault-key derivation.
**Author:** Ken Romero, with synthesis assistance from Claude.
**Status:** Finding recorded. Scope widened after empirical test. CLI-emit surface patched (`crates/zp-cli/src/emit.rs`, 2026-07-18); remaining CLI keyring surfaces enumerated below and pending same treatment. Vault-key derivation path still pending. Sidesteppable by local-inference configuration in current investigations.

---

## Finding (widened 2026-07-18 evening)

The substrate's audit-signing path (server boot) composes with the sovereignty provider layer via `zp_keys::load_sovereign_root()` — the canonical singular-sovereign-root loader that tries the standard OS Keychain fast path first, then falls through to the active sovereignty provider (Trezor, YubiKey, Ledger, OnlyKey) if the Keychain is empty. That's the composed path.

**Multiple non-composed paths exist alongside it.** Each is an independent load site that calls the credential-store-only primitive (`keyring.load_genesis_secret()`, `keyring.genesis_secret()`, `keyring.load_operator()`) directly, bypassing the sovereignty provider layer. Under hardware-wallet Genesis, all of them silently fail — the credential store is empty because the Genesis material is wrapped under the hardware token.

**Enumerated non-composed surfaces (as of 2026-07-18):**

| Surface | Symptom under hardware Genesis | Status |
|---|---|---|
| `zp_keys::vault_key::resolve_vault_key()` | Server WARN: "No vault key available" at boot; vault operations disabled | **Patched 2026-07-18** — tries `load_sovereign_root()` first, falls back to keyring-direct path for backward compat. New `VaultKeySource::SovereigntyProvider` variant. |
| `zp-cli` `zp emit` (both operator load + audit signer derivation) | Fails: "No operator key available — run `zp init` first" | **Patched 2026-07-18** — routes through `load_sovereign_root()` |
| `Keyring::genesis_record_path()` (name/docstring drift) | Docstring said "pass this to load_sovereign_root" but method returns the certificate path, not the sovereignty descriptor. Two hours of bootstrap time lost 2026-07-18 to this. | **Patched 2026-07-18** — renamed to `genesis_certificate_path()`; `genesis_record_path()` retained as `#[deprecated]` alias with corrected doc pointing to `zp_core::paths::genesis_record_path` for the sovereignty path. |
| `zp-cli` `zp health` Genesis check | Fails: "Genesis secret not in OS credential store" (misleading under hardware Genesis) | **Patched 2026-07-18** — migrated in the mass CLI pass to `crate::commands::load_genesis_secret_composed()`. |
| All other `zp-cli` verbs calling `keyring.load_operator()`, `keyring.load_genesis()`, or `keyring.genesis_secret()` | Same class — silent failure or misleading error under hardware Genesis | **Patched 2026-07-18** — mass migration to `crate::commands::load_operator_composed`, `load_genesis_composed`, `load_genesis_secret_composed` drop-in helpers. Coverage: commands.rs (7 sites), run.rs (3 sites), emit.rs internal (1 site), main.rs (~19 sites). Composed helpers route through `zp_keys::load_sovereign_root`; single sovereign-root unwrap ceremony shared across the CLI process via process-scoped OnceLock. |
| `zp doctor` Genesis credential-store check (line reporting `✓ Genesis secret: present in credential store`) | Incoherent report — check passes only when credential store holds Genesis, which under hardware providers it doesn't. May be checking a legacy fallback file. | Pending diagnosis |

Note: `zp doctor` returned `✓ Genesis secret: present in credential store` on APOLLO 2026-07-18 despite the credential store being empty under Trezor Genesis. Either doctor is checking a fallback path that a Trezor install still populates (e.g., `~/ZeroPoint/keys/genesis.record` metadata) and misreporting it as the credential store, or the drift is even wider. Requires separate diagnosis.

Consequence overall: the CLI surface is not usable for signing operations under hardware-wallet Genesis until each surface is migrated to route through `load_sovereign_root()`. The audit signer works (server-side, already composed); everything CLI-side that needs a signing key does not.

Observed symptom (2026-07-18, APOLLO):

```
INFO  zp_keys::sovereignty::hardware::trezor: Genesis secret decrypted via Trezor CipherKeyValue
INFO  zp_server: Identity from Operator key (sovereignty provider): b8770ce49617...b8661f00
WARN  zp_server: ⚠ Vault key not available: invalid key material: No vault key available.
                 Run `zp init` to create your Genesis key. — operator rotation,
                 credential decryption, and vault operations are disabled.
```

Same Genesis material, two independent load paths. One succeeds; the other silently fails and disables vault operations.

---

## Structural diagnosis — one of your own working principles, made visible

From CLAUDE.md workflow heuristics — *Singular sovereign root: one authentication, everything derived*:

> When a system needs operator authentication to access secrets, design for one sovereign root — one credential, one prompt, one ceremony — from which every other secret derives. The credential store holds exactly one biometric-gated item; all other secrets are either derived in memory from that root, or stored encrypted in a vault that the root unlocks. There is no third category.

Applied here: the substrate has drifted into **two independent "load sovereign root" paths**. Path A (audit signer) composes with the sovereignty provider — knows about Trezor, YubiKey, Ledger, OnlyKey. Path B (vault-key derivation) does not — knows only OS credential store and legacy file.

CLAUDE.md's diagnostic posture predicts this exact shape:

> if a single operator action triggers N authentication prompts, the architecture has drifted into N independent secrets

The variant here is not N prompts — it's one prompt (Trezor) + one silent-empty (Keyring), producing vault-disabled state. Same structural drift, different symptom.

## Why it worked before

When Genesis lived in the OS credential store, both paths hit the same Keyring, both succeeded. When Genesis moved to hardware wallet, the audit signer was updated to compose with the sovereignty provider layer; the vault-key derivation path was not. The drift was latent — dormant until sovereign root selection made one of the paths silently empty.

This is not a system failure. It is a **structural gap that was always there**, made load-bearing when the operator switched sovereignty provider. The gap is code-level, not data-level: no data was lost, no key was rotated, no credential was invalidated. Both paths look at real Genesis material; only one knows where to look for it now.

---

## Fix path — architecturally clean

**Composition, not duplication.** The correct fix is to make vault-key derivation compose with the sovereignty provider layer — the same way audit signing does. After the sovereignty provider unwraps Genesis at boot (whatever provider is active), the unwrapped material becomes the substrate's singular sovereign root for the process lifetime. Both audit signing and vault-key derivation read from the same in-memory cache. One unwrap ceremony, everything derived.

Concretely, in `crates/zp-keys/src/vault_key.rs::resolve_vault_key()`:

Current shape (offending):
```rust
match keyring.load_genesis_secret() {
    Ok((secret, from_credential_store)) => {
        let key = derive_vault_key(&secret);
        // …
```

Proposed shape:
```rust
match sovereignty::load_active_genesis_secret() {
    Ok(secret) => {
        let key = derive_vault_key(&secret);
        // source attribution derives from sovereignty provider metadata
        // …
```

Where `sovereignty::load_active_genesis_secret()` is the single canonical loader: it queries the sovereignty provider registry, dispatches to whichever provider holds the operator's Genesis (OS credential store, Trezor, YubiKey, Ledger, OnlyKey), returns the unwrapped material. Legacy fallbacks (`SECRETS_MASTER_KEY` env var, legacy file) stay as inner branches, in order of preference, gated behind the sovereignty provider miss.

The corollary: `keyring.load_genesis_secret()` becomes an implementation detail of the OS-credential-store provider only. Not called directly by consumers. Its current direct-call sites (any of them outside the sovereignty-provider path) all become bugs by this rule — the discipline pin `singular_sovereign_root` should catch them.

### Discipline pin follow-up

Add a `discipline:pin:singular_sovereign_root` receipt / build-time check with the following invariant:

> All Genesis-secret-load sites route through `sovereignty::load_active_genesis_secret()`. Direct calls to `keyring.load_genesis_secret()` or equivalent provider-specific loaders outside the sovereignty provider path fail the pin.

Prevents this drift class from recurring next time a new provider (e.g., BIP-39 seed phrase) is added.

---

## Composition with existing specs

- **`SUBSTRATE-EXECUTION-ARCHITECTURE-2026-07.md`** — this finding is Layer A discipline (composition contracts). Vault-key derivation and audit signing must compose against the same sovereignty-provider surface.
- **`ENCRYPTED-STORAGE-ARCHITECTURE-2026-07.md`** — the vault is the derived-secret store; its unlock material must trace to the operator's active sovereign root, not to any particular provider's local persistence.
- **`GENESIS-ROTATION-CEREMONY-2026-07.md`** — Genesis rotation must invalidate the derived vault key alongside the sovereign root. Under the proposed fix, this happens naturally: rotate the sovereign root, the next `sovereignty::load_active_genesis_secret()` returns the new secret, derived vault key changes accordingly.
- **`BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md`** — recovery via `zp recover` currently only knows how to restore to the OS credential store. Post-fix, recovery must also restore to whichever sovereignty provider the operator selects for the recovered substrate.

## What this does NOT affect

- **Observer-windows investigation Phase 1** (`OBSERVER-WINDOWS-INVESTIGATION-2026-07.md`) — local-Ollama configuration sidesteps the vault-key path entirely. Regent inference call is HTTP against 127.0.0.1:11434 with no vault-decrypted secret. Officer sweeps, chain writes, canary discipline, cognitive cycle — none touch vault. Investigation viable while this finding is unrepaired.
- **Chain integrity** — no chain state is corrupted by this finding. Chain is truth; the finding is that a derived layer above the chain has two independent load paths.
- **Audit signing** — the audit path is the one that already composes. Unaffected.

## What this DOES affect

- **Cloud inference** — API keys typically live in vault; blocked until fix lands.
- **Credential decryption in general** — anything vault-encrypted (Anthropic/OpenAI/Abacus keys, cloud service tokens, external anchor credentials) is unavailable to the substrate until fix lands or the operator moves sovereign root back to OS credential store.
- **Operator key rotation** — the sovereignty provider layer's rotation semantics don't compose with vault re-encryption yet; separate follow-up.
- **`zp doctor` and `zp health` diagnostics** — both are silent on this specific drift and should be updated to explicitly report "sovereignty provider ↔ vault-key composition status" as a checked property. Companion hygiene bugs: `zp health` says "run `zp init`" when Genesis is present under a hardware provider; `zp doctor` misses the vault-key warning entirely.

---

## CLAUDE.md workflow heuristics this finding exercises

- *Singular sovereign root: one authentication, everything derived.* — the finding IS this heuristic firing in the wild.
- *When two reasonable architectural models conflict over the same surface, half-state is the failure mode.* — Path A (composed) + Path B (uncomposed) is half-state for sovereign-root load.
- *Operational configuration with multiple write paths is structural drift waiting to happen.* — the diagnostic pattern.
- *Verify before commit.* — this finding would not have surfaced without APOLLO walkthrough. The audit's assumption that "runtime state is verifiable from source" was insufficient; direct observation was required.
- *Config reflects today, not roadmap.* — the fix should land as executable code, not as design intent that the config file assumes.

## Follow-up tasks

- Implement `sovereignty::load_active_genesis_secret()` unified loader.
- Migrate `vault_key.rs::resolve_vault_key()` to route through it.
- Migrate any other direct callers of `keyring.load_genesis_secret()` outside the sovereignty-provider path.
- Land `discipline:pin:singular_sovereign_root` check (build-time or CI-time).
- Update `zp doctor` and `zp health` to explicitly diagnose sovereignty-provider ↔ vault-key composition.
- File `zp health` red-herring bug: "Genesis secret not in OS credential store" is misleading when Genesis is present under a hardware provider.
- Amend `BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md` to name provider-scoped recovery.

None of the above blocks the observer-windows investigation running on local-Ollama configuration. All of them should land before the substrate ships to any operator who might use cloud inference under hardware sovereignty.
