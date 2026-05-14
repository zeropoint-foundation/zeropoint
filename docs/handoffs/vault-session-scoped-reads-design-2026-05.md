# Vault Session-Scoped Reads — Design One-Pager

*2026-05-14. Deliverable for substrate hardening pass (#91). Read before
implementing. Refs: substrate-readiness-checkpoint-2026-05.md, Task #150.*

---

## 1 · The problem

`zp configure exec --name ironclaw -- ironclaw` resolves 32 env vars from
the vault and then `exec()`s the tool. The user sees 5–9 Touch ID prompts
across that single invocation. All 32 env vars should require exactly one
authentication.

---

## 2 · Current per-read flow (traced from source)

```
zp configure exec
  │
  ├── resolve_vault_key(kr)                                 [main.rs:1071]
  │     └── keyring.load_genesis_secret()                  [keyring.rs:335]
  │           └── load_genesis_from_credential_store()     [keyring.rs:619]
  │                 └── OnceLock: FIRST CALL hits Keychain
  │                       ├── Standard path (os-keychain):
  │                       │     keyring::Entry.get_password() → "zeropoint-genesis"
  │                       │     macOS Keychain ACL dialog → may prompt
  │                       └── Biometric path (biometric-keychain feature active):
  │                             secure_keychain::load()    [touchid.rs:559]
  │                               SecItemCopyMatching("zeropoint-genesis-bio")
  │                               kSecAccessControlBiometryCurrentSet
  │                               → Touch ID EVERY CALL, NO CACHE ← seam
  │
  ├── BLAKE3(genesis, "zp-credential-vault-v1") → vault_master_key
  │
  ├── CredentialVault::load_or_create(&vault_master_key, vault.json)
  │     └── Loads encrypted entries from disk; holds master_key in memory
  │
  ├── vault.resolve_tool_env("ironclaw")
  │     └── 32× vault.retrieve(key)
  │           └── decrypt_value(&self.master_key, ciphertext)
  │                 *** NO KEYCHAIN ACCESS — pure in-memory decryption ***
  │
  └── emit_launch_receipt(...)                             [main.rs:1385]
        ├── open_keyring()  ← FRESH Keyring instance
        │
        ├── keyring.load_operator()                        [run.rs:275]
        │     └── keyring.load_genesis_secret()
        │           └── load_genesis_from_credential_store()
        │                 └── OnceLock: cache hit if standard path succeeded
        │                     MISS if biometric path was used upstream ← gap
        │
        └── keyring.load_genesis_secret()                  [run.rs:282]
              └── load_genesis_from_credential_store()
                    └── OnceLock: cache hit
```

### Where the prompts come from

**The vault decryption itself is innocent.** `CredentialVault` holds the
master key in memory and all 32 `retrieve()` calls are pure in-memory
ChaCha20 — zero Keychain touches.

**Two distinct Keychain paths exist with separate caching properties:**

| Path | Item | Cached? | Prompt trigger |
|------|------|---------|----------------|
| `load_genesis_from_credential_store()` | `zeropoint-genesis` (standard) | Yes — `OnceLock` in keyring.rs:619 | macOS ACL dialog (once per binary build, not biometric) |
| `secure_keychain::load()` | `zeropoint-genesis-bio` (biometric-gated) | **No cache** | Touch ID on every call — OS-enforced by `kSecAccessControlBiometryCurrentSet` |

When the binary is built with `biometric-keychain` AND code-signed with
Keychain entitlements, the biometric item exists and `load_touchid_secret_v2()`
calls `secure_keychain::load()` — which triggers Touch ID unconditionally
each time. The standard-path `OnceLock` does not protect this code path.

**The `emit_launch_receipt` gap**: Even in the standard (non-biometric) path,
`emit_launch_receipt` opens a fresh `Keyring` instance and calls
`load_operator()` → `load_genesis_secret()` + a direct `load_genesis_secret()`
call. Both hit the process-scoped `OnceLock` cache correctly. However, if the
upstream `resolve_vault_key()` took the biometric path (no OnceLock), and the
standard item doesn't exist, both receipt calls also fall through to biometric
loads — two more uncached Touch ID prompts.

**Why the count is 5–9, not deterministic**: The range reflects whether
macOS has a cached Keychain ACL grant for the current binary. After a
`cargo build`, the binary hash changes and macOS re-prompts. Each
`secure_keychain::load()` call is always a new Touch ID. Combined with
two receipt-path calls, the total depends on build freshness and which
code branches execute.

---

## 3 · Proposed session-scoped flow

Goal: **one Touch ID per `zp configure exec` invocation**, regardless of
whether `biometric-keychain` is active or the binary was just rebuilt.

### Fix A — Cache `secure_keychain::load()` (primary fix)

Add a process-scoped `OnceLock` inside `secure_keychain::load()` analogous
to the one in `load_genesis_from_credential_store()`:

```rust
// In crates/zp-keys/src/sovereignty/touchid.rs, secure_keychain mod

#[cfg(not(test))]
pub fn load() -> Result<[u8; 32], KeyError> {
    use std::sync::OnceLock;
    static CACHED: OnceLock<Result<[u8; 32], String>> = OnceLock::new();
    let result = CACHED.get_or_init(|| {
        load_uncached().map_err(|e| format!("{}", e))
    });
    match result {
        Ok(s) => Ok(*s),
        Err(msg) => Err(KeyError::CredentialStore(msg.clone())),
    }
}

fn load_uncached() -> Result<[u8; 32], KeyError> {
    // existing SecItemCopyMatching logic, unchanged
}
```

This makes the biometric path and the standard path symmetric: both
cache after the first call. The Touch ID dialog appears exactly once
per process lifetime.

### Fix B — Thread genesis secret through emit_launch_receipt (belt-and-suspenders)

The receipt emission code re-derives the genesis secret from Keychain even
though it was already loaded upstream. Thread it in:

```rust
// In crates/zp-cli/src/run.rs
pub struct LaunchReceiptFields<'a> {
    // ... existing fields ...
    pub genesis_secret: Option<&'a [u8; 32]>,  // caller passes already-loaded secret
}

pub fn emit_launch_receipt(fields: &LaunchReceiptFields, ...) -> Result<String> {
    let genesis_secret: [u8; 32];
    let _owned;
    let secret_ref = if let Some(s) = fields.genesis_secret {
        s
    } else {
        _owned = keyring.load_genesis_secret()?.0;
        &_owned
    };
    let audit_seed = zp_keys::derive_audit_signer_seed(secret_ref);
    // ...
}
```

Call site in `main.rs` passes `genesis_secret: Some(&genesis_secret_bytes)`,
where `genesis_secret_bytes` was loaded once during `resolve_vault_key()`.
This eliminates the receipt path's independent Keychain touch entirely,
making the end-to-end call count exactly 1 regardless of caching behavior.

### Fix C — Single vault-key derivation point (structural cleanup)

The vault master key is deterministic: `BLAKE3(genesis, context)`. Once
resolved, there is no reason to re-derive it. The current code already
threads `padded_key` correctly through the exec path (line 1123 → 1303
in main.rs). Fix B above extends this principle to the receipt path.

No new `OnceLock` is needed for the vault master key itself — it follows
from the genesis secret being cached.

---

## 4 · Security trade-offs

### What the wrapping key in memory means

The vault master key lives in `CredentialVault.master_key: [u8; 32]` with
`Zeroizing` drop semantics (keyring.rs `derive_vault_key_local` returns
`Zeroizing<[u8; 32]>`; `CredentialVault::Drop` calls `self.master_key.zeroize()`).

For `zp configure exec`, the exposure window is:

```
resolve_vault_key() called
    │
    ▼  ← master_key lives in memory here (~milliseconds)
CredentialVault created and resolved
    │
    ▼
emit_launch_receipt() completes
    │
    ▼
exec() syscall — zp process image REPLACED by ironclaw
    │
    ▼  ← zp's memory space is released; master_key is gone
```

The `exec()` syscall replaces the process image entirely. The vault master
key never lives in the child process. Exposure window is bounded by the time
between `resolve_vault_key()` and the `exec()` call — typically under 100ms.

### `secure_keychain` OnceLock and the cached secret

Caching the biometric-path genesis secret in a `OnceLock<Result<[u8;32], _>>`
introduces a process-lifetime secret in memory. Risk assessment:

| Risk | Severity | Mitigator |
|------|----------|-----------|
| Process memory read (same user) | Low | exec() terminates the zp process immediately; window is <100ms |
| Process memory read (cross-user) | N/A | macOS ASLR + process isolation |
| Swap exposure | Low | Key is 32 bytes in a `[u8;32]`; does NOT use `Zeroizing` in a `OnceLock` (OnceLock can't zeroize on drop since the cache lives for process lifetime by design) |
| Crash dump exposure | Low | Already present — `CredentialVault.master_key` has the same exposure in the existing code |

**The swap/dump exposure is the only net-new risk.** The genesis secret is
already loaded into memory via the existing `OnceLock` in
`load_genesis_from_credential_store()`. Adding a second `OnceLock` for the
biometric path does not materially change the attack surface — it only
prevents the secret from being loaded twice.

Mitigation (deferred, not blocking): `mlockall(MCL_CURRENT | MCL_FUTURE)`
in the zp CLI binary to prevent process memory from being paged out. This
is a single call in `main()` and applies to both existing and new caches.

### TTL considerations

For `zp configure exec`, "process lifetime" IS the TTL — exec() terminates
the zp process, so the secret is gone. There is no need for a separate TTL
timer.

For future interactive workflows where zp stays alive longer (e.g., a
zp REPL or daemon), a TTL-based eviction scheme would be needed. That is
out of scope for this fix.

---

## 5 · Implementation surface

| File | Change | Why |
|------|--------|-----|
| `crates/zp-keys/src/sovereignty/touchid.rs` | Add `OnceLock` to `secure_keychain::load()` | Fix A — eliminates uncached biometric reads |
| `crates/zp-cli/src/run.rs` | Add `genesis_secret: Option<&[u8; 32]>` to `LaunchReceiptFields`; use it instead of re-calling `load_genesis_secret()` | Fix B — eliminates receipt path Keychain re-read |
| `crates/zp-cli/src/main.rs` | Pass resolved genesis secret into `emit_launch_receipt` | Fix B call site |
| `crates/zp-cli/src/emit.rs` | Same pattern as run.rs if `emit_*` functions follow the same re-load pattern | Fix B parity |

Files NOT touched:
- `crates/zp-trust/src/vault.rs` — vault decryption is already session-scoped correctly
- `crates/zp-keys/src/keyring.rs` — `load_genesis_from_credential_store` OnceLock already correct
- `crates/zp-keys/src/vault_key.rs` — `resolve_vault_key` flow is already correct

---

## 6 · Before implementing: instrumentation step

**Confirm the call site before writing code.** Add a `tracing::warn!` or
`eprintln!` to `secure_keychain::load()` with a backtrace capture, then run:

```sh
RUST_LOG=debug zp configure exec --name ironclaw -- echo done 2>&1 | grep -i "biometric\|secure_keychain\|genesis"
```

Expected: the log shows either 0 or 1 call to `secure_keychain::load()`.
If it shows > 1, Fix A is confirmed and the location is clear. If it shows
0, the prompts are from the standard keychain ACL dialog and Fix B alone
may be sufficient.

---

## 7 · Acceptance criterion

After this lands:

```sh
zp configure exec --name ironclaw -- echo done
```

Shows exactly **one** Touch ID prompt (or zero if the process-scoped cache
from a prior invocation is warm — but there is no cross-process cache, so
it will be one per `zp` invocation). The 32 env var reads produce no
additional prompts.

---

## 8 · Follow-on diagnosis — the remaining second prompt (2026-05-14)

Fix A + Fix B landed as `0aab7b8` and reduced prompts from 5–9 to **2**.
Instrumentation with backtrace was added to four entry points and run in
both `--features full` and `--features full,biometric-keychain` builds to
pinpoint the second prompt.

### Instrumentation findings

```
RUST_LOG=warn RUST_BACKTRACE=1 ZP_KEYCHAIN_TEST_NAMESPACE=1 \
  zp configure exec --name ironclaw -- echo done
```

Both builds emitted exactly one warning line:

```
WARN zp::biometric: load_genesis_from_credential_store_uncached called,
  item=zeropoint-genesis-test/genesis-secret-test
  → via resolve_vault_key → main.rs:1071
```

Counts per instrumentation point:

| Call site | Full build | Full+biometric-keychain |
|-----------|-----------|------------------------|
| `TouchIdProvider::load_secret` | 0 | 0 |
| `secure_keychain::load` (wrapper) | 0 | 0 |
| `secure_keychain::load_uncached` | 0 | 0 |
| `load_genesis_from_credential_store_uncached` | 1 | 1 |

**`zp configure exec` never invokes the sovereignty provider.** The
configure exec code path goes exclusively through
`keyring.load_genesis_secret()` → `load_genesis_from_credential_store()`
(standard Keychain, OnceLock). Fix A and Fix B are both correct and the
OnceLock for `secure_keychain` is working.

### Root cause of the second prompt

The second prompt comes from the **ZP server process** (`zp serve`), not
from `zp configure exec`. The server is a separate process started by
`./zp-dev.sh`. Its startup path is:

```
AppState::init()                            [zp-server/src/lib.rs:571]
  └── load_or_create_identity()
        └── keyring.load_operator()         [path 1a — standard Keychain]
              → succeeds for Touch ID mode
  └── load_genesis_secret_from_provider()  [line 595 — ALWAYS called]
        └── provider.load_secret()
              └── TouchIdProvider::load_secret()
                    └── load_touchid_secret_v2()
                          └── secure_keychain::load()  ← Touch ID prompt
```

`load_genesis_secret_from_provider()` derives the audit signer key and
always goes through the sovereignty provider, even for Touch ID mode where
the genesis secret is already available in the standard Keychain (written
there by `save_touchid_secret_v2()` as a bridge item). The comment in the
function says "the credential-store fast path doesn't hold the secret on
hardware-wallet sovereignty modes" — this is true for Trezor/YubiKey but
false for Touch ID.

Before Fix A: the server's `secure_keychain::load()` was uncached → N
biometric prompts per server process (one per code path that invoked it).
After Fix A: OnceLock → 1 biometric prompt per server process.

Total before Fix A: N server prompts + 1 configure-exec ACL dialog = 5–9.
Total after Fix A:  1 server prompt + 1 configure-exec ACL dialog = 2.

### Fix C — standard Keychain fast path in load_genesis_secret_from_provider

`load_genesis_secret_from_provider()` in `zp-server/src/lib.rs` should
try `keyring.load_genesis_secret()` (standard Keychain, already cached in
the OnceLock from the `load_or_create_identity()` call above) before
invoking the sovereignty provider. Fall through to the sovereignty provider
only if the standard Keychain doesn't have the secret — which is only true
for hardware wallet modes (Trezor, YubiKey, etc.) that never write to the
standard Keychain during enrollment.

```rust
fn load_genesis_secret_from_provider(genesis_record_path: &Path) -> Result<[u8; 32], String> {
    // ... read genesis.json, resolve mode ...

    // Fast path: standard Keychain (OnceLock hit — load_or_create_identity
    // already touched it above). Works for Touch ID, login-password, and
    // file-based modes. Hardware wallets fall through.
    if let Some(home_dir) = genesis_record_path.parent() {
        if let Ok(keyring) = zp_keys::Keyring::open(home_dir.join("keys")) {
            if let Ok((secret, _)) = keyring.load_genesis_secret() {
                return Ok(secret);
            }
        }
    }

    // Sovereignty-provider path for hardware wallets.
    let provider = zp_keys::provider_for(mode);
    provider.load_secret().map_err(|e| format!("..."))
}
```

**Implementation surface for Fix C:**
- `crates/zp-server/src/lib.rs` — `load_genesis_secret_from_provider()`

**Acceptance criterion after Fix C:** a full `./zp-dev.sh` restart cycle
produces exactly **1** prompt (the standard Keychain ACL dialog for
`zp configure exec`). The server startup produces no additional prompt
because it hits the OnceLock-cached standard Keychain secret.

---

## Refs

- `crates/zp-keys/src/sovereignty/touchid.rs` — `secure_keychain::load()` (line 559)
- `crates/zp-keys/src/keyring.rs` — `load_genesis_from_credential_store()` OnceLock (line 619)
- `crates/zp-trust/src/vault.rs` — `CredentialVault` — already session-scoped
- `crates/zp-keys/src/vault_key.rs` — `resolve_vault_key()` — single call in exec path
- `crates/zp-cli/src/main.rs:1066–1451` — configure block
- `crates/zp-cli/src/run.rs:270–330` — `emit_launch_receipt`
- Task #150 — this work
- Task #91 — hardening pass this belongs to
