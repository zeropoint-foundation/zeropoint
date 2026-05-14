# ZeroPoint Discipline Pins

*Discipline pins are structural rules for the ZeroPoint codebase that
cannot be expressed as type-system constraints but are load-bearing for
correctness or security. Each pin names a rule, specifies what it
forbids, where violations appear, and how enforcement runs.*

*Pattern: one canonical helper introduced for a cross-cutting concern;
discipline pin prevents the concern from re-fragmenting. Precedent:
Seams 5/17/19 in `docs/STRUCTURAL-AUDIT-2026-05.md` (verify_signature,
canonical JSON, path resolution).*

---

## singular_sovereign_root

**Landed:** 2026-05-14. Commits 7f6397b, eb1975f, aba2b26.
**Task:** #152. **Hardening pass:** #91.

### Rule

There is exactly one sovereign root per ZeroPoint process: Genesis. Every
other secret in the substrate is either:

1. **Derived from Genesis in memory** (vault master key, audit signer
   seed, agent certificate material), or
2. **Stored in the vault** (`vault.json`, ChaCha20-Poly1305 at rest)
   and decrypted on demand using the in-memory vault master key.

There is no third category. No secret stored in the OS credential store
independently, outside the Genesis item, with its own biometric gate.

The canonical loader is `zp_keys::sovereignty::load_sovereign_root()`.
It wraps a process-scoped `OnceLock` — exactly one sovereignty ceremony
per process lifetime.

### What this forbids

| Pattern | Forbidden outside | Allowed in |
|---------|------------------|-----------|
| `keyring::Entry::get_password()` | everywhere | `crates/zp-keys/src/keyring.rs` only |
| `keyring::Entry::set_password()` | everywhere | `crates/zp-keys/src/keyring.rs` only (one write site: genesis enrollment) |
| `SecItemCopyMatching` | everywhere | `crates/zp-keys/src/sovereignty/touchid.rs` only |
| `SecItemAdd` | everywhere | `crates/zp-keys/src/sovereignty/touchid.rs` only |
| `SecItemDelete` | everywhere | `crates/zp-keys/src/sovereignty/touchid.rs` and `crates/zp-keys/src/keyring.rs` (genesis clear) |
| `provider.load_secret()` direct call | everywhere | `crates/zp-keys/src/sovereignty/mod.rs` only (inside `load_sovereign_root_uncached`) |
| `bioutil` subprocess | everywhere | `crates/zp-keys/src/sovereignty/touchid.rs` only |
| `fprintd-verify` subprocess | everywhere | `crates/zp-keys/src/sovereignty/fingerprint.rs` only |
| Hardware-wallet APDU calls | everywhere | `crates/zp-keys/src/sovereignty/hardware/` only |

### Enforcement scan

Run before merging any PR that touches credential loading:

```sh
# Forbidden outside crates/zp-keys/src/keyring.rs and sovereignty/
rg 'keyring::Entry' --type rust \
    --glob '!crates/zp-keys/src/keyring.rs' \
    --glob '!crates/zp-keys/src/sovereignty/**'

# Forbidden outside touchid.rs
rg 'SecItemCopyMatching|SecItemAdd|SecItemDelete' --type rust \
    --glob '!crates/zp-keys/src/sovereignty/touchid.rs'

# Forbidden outside sovereignty/mod.rs
rg '\.load_secret\(\)' --type rust \
    --glob '!crates/zp-keys/src/sovereignty/mod.rs' \
    --glob '!crates/zp-keys/src/sovereignty/**'

# Forbidden outside their respective provider modules
rg '"bioutil"' --type rust \
    --glob '!crates/zp-keys/src/sovereignty/touchid.rs'
rg '"fprintd-verify"' --type rust \
    --glob '!crates/zp-keys/src/sovereignty/fingerprint.rs'
```

All scans must return zero results. CI integration: add as a step in
the pre-merge check alongside `cargo test` and `cargo clippy`.

### Tests

`crates/zp-keys/src/sovereignty/mod.rs` test module contains:

- `provider_for_genesis_record_parses_known_modes` — verifies the JSON
  parser correctly maps all sovereignty mode strings to providers
- `provider_for_genesis_record_errors_on_missing_file` — actionable error
  when genesis.json is absent
- `provider_for_genesis_record_errors_on_missing_mode_field` — actionable
  error when the mode field is absent or malformed
- `load_sovereign_root_errors_clearly_on_missing_genesis` — the function
  does not panic on a cold start with no genesis record

Empirical call-count verification (N==1 per process) is documented in
`docs/handoffs/vault-session-scoped-reads-design-2026-05.md §8` —
confirmed via `RUST_BACKTRACE=1` instrumentation run.

### Rationale

Direct credential-store reads scattered across multiple crates compound
with every new provider added:

- Each new provider that stores its own derived material → another
  biometric gate → another re-prompt for the operator.
- Multi-quorum sovereignty (2-of-3 Trezors, per CLAUDE.md) multiplies
  every independent read by M confirmations, not 1.
- Audit-chain authority degrades when the audit signer can be loaded
  independently of Genesis (the chain's "signed by the operator"
  claim becomes weaker if the signer key has its own credential-store
  entry).

See `docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md` for the full architectural
argument.

### Migration history (APOLLO, 2026-05-14)

Three legacy Keychain entries were found on APOLLO before this pin landed:

| Entry | Status | Fix |
|-------|--------|-----|
| `zeropoint` / `vault-master-key` | Never used by current code (pre-Genesis relic) | `zp keychain cleanup --delete` |
| `zeropoint-operator` / `operator-secret` | Written (best-effort), never read | Removed write in 7f6397b; cleanup via `zp keychain cleanup --delete` |
| `zeropoint-genesis` / `genesis-secret` | Legitimate sovereign root | Keep |

---

## (future pins go here)
