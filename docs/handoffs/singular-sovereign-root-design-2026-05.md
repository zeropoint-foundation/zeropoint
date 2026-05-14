# Singular Sovereign Root — Design One-Pager

*2026-05-14. Path B step 3 per substrate-readiness-checkpoint-2026-05.md.
Investigation tasks completed before writing. Bring back for review before
authorizing implementation. Refs: Task #152, #91, #150.*

---

## 1 · Current state — call-site catalog

### The three Keychain entries on APOLLO

| Service | Account | Created | Code status | Action |
|---------|---------|---------|-------------|--------|
| `zeropoint` | `vault-master-key` | 2026-03-22 | **Never written or read by any current code** | Relic — `zp keychain cleanup` removes it |
| `zeropoint-operator` | `operator-secret` | 2026-04-09 | Written best-effort (silently ignored on failure); **never read in production** | Remove the write; canonical store is already `operator.secret.enc` |
| `zeropoint-genesis` | `genesis-secret` | 2026-04-21 | Legitimate sovereign root. Read via OnceLock. | Keep |

A fourth entry exists in `biometric-keychain` builds:

| Service | Account | Code status | Action |
|---------|---------|-------------|--------|
| `zeropoint-genesis-bio` | `genesis-secret-bio` | Written/read via `secure_keychain` (Security.framework FFI). OnceLock-cached by Fix A. | Keep |

### `zeropoint` / `vault-master-key` — investigation finding

No write site exists in the workspace. `rg 'vault.master.key\|vault_master_key'`
returns zero Rust hits. The vault master key is and has always been derived
in memory:

```
vault_key.rs:69–76  derive_vault_key()
  BLAKE3-keyed(genesis_secret, "zp-credential-vault-v1")  → [u8; 32]
```

The Keychain entry on APOLLO is a relic from a pre-Genesis design iteration
(2026-03-22, before Genesis became canonical on 2026-04-21). Nothing reads
it. No code migration required — only a cleanup command.

### `zeropoint-operator` / `operator-secret` — investigation finding

**Write site (best-effort):** `keyring.rs:422`

```rust
pub fn save_operator(&self, operator: &OperatorKey) -> Result<(), KeyError> {
    // ... always writes operator.secret.enc (canonical, ChaCha20) ...
    let _ = save_operator_to_credential_store(&secret);  // ← best-effort, ignored
}
```

`save_operator_to_credential_store()` at `keyring.rs:688` calls
`keyring::Entry::new("zeropoint-operator", "operator-secret").set_password(...)`.
On APOLLO, this triggers an ACL grant dialog (once per binary build) even
though the value is never read back.

**Read site: dead code.** `load_operator_from_credential_store()` at
`keyring.rs:710` is marked `#[allow(dead_code)]` and not called anywhere.
`load_operator()` at `keyring.rs:466` explicitly skips the Keychain:

```rust
// Avoiding load_operator_from_credential_store() eliminates a separate
// macOS Keychain prompt...
// The genesis load below is the single keychain touch point.
```

The canonical operator-secret store is `operator.secret.enc`, a
ChaCha20-Poly1305 blob on disk, encrypted under the vault key derived from
Genesis. It already exists, is always written, and is already what
`load_operator()` reads.

### Full credential-store call-site catalog

```
keyring::Entry calls (all in crates/zp-keys/src/keyring.rs):
  :585  save_genesis_to_credential_store()  — genesis write (enrollment)
  :647  load_genesis_from_credential_store_uncached()  — genesis read (OnceLock)
  :691  save_operator_to_credential_store()  — operator write (best-effort, remove)
  :713  load_operator_from_credential_store()  — operator read (dead code, remove)
  :744  clear_genesis_from_credential_store()  — genesis delete (recovery)

Security.framework FFI (all in crates/zp-keys/src/sovereignty/touchid.rs):
  :518  SecItemAdd  — biometric genesis store
  :536  SecItemAdd  — biometric genesis store retry
  :626  SecItemCopyMatching  — biometric genesis load (OnceLock)
  :707  SecItemDelete  — biometric cleanup

bioutil calls (crates/zp-keys/src/sovereignty/touchid.rs):
  verify_touchid()  — application-layer biometric check (pre-flight during
  enrollment; fallback in load_touchid_secret_v1 when biometric item missing)

fprintd-verify (crates/zp-keys/src/sovereignty/fingerprint.rs):
  verify_presence()  — Linux fingerprint check; contained within module

Hardware-wallet APDU (crates/zp-keys/src/sovereignty/hardware/trezor.rs):
  All within hardware/ — already in scope
```

**Violations of the singular-root principle:**
- `keyring.rs:691` — operator write outside sovereignty/ (best-effort, still pollutes Keychain)
- `keyring.rs:713` — operator read outside sovereignty/ (dead code, but dangerous precedent)
- `zp-server/src/lib.rs:279,320` — `provider.load_secret()` called directly in server lib rather than through canonical loader (fixed by Fix C fast path, but the underlying sovereignty call is still there for hardware-wallet modes; the server lib should not know how to invoke providers)

### Why APOLLO shows two ACL grants per workflow invocation

After Fixes A + B + C, each individual process (`zp` CLI or `zp serve`) touches
the Keychain exactly once per process lifetime (OnceLock). But a full restart
workflow involves two processes:

1. **`zp serve` process** — `load_or_create_identity()` reads genesis via
   `load_genesis_from_credential_store()` (path 1a → operator load). Server
   process OnceLock primes. Fix C fast-paths the audit-signer read within the
   same server process (cache hit). **1 ACL grant** from the server process.

2. **`zp configure exec` process** — `resolve_vault_key()` reads genesis via
   `load_genesis_from_credential_store()`. Process OnceLock primes. All
   subsequent reads (emit_launch_receipt, etc.) hit cache. **1 ACL grant** from
   the CLI process.

OnceLock is process-scoped. Two independent processes, each authenticating once,
is the correct and irreducible minimum. The two ACL grants are expected and
correct — once "Always Allow" is clicked for each, subsequent runs show zero
grants.

The `zeropoint-operator` write adds a third ACL grant (Keychain write ACL, not
read ACL) whenever `save_operator()` is called. This is the vestigial violation.

---

## 2 · Proposed canonical loader API

```rust
// crates/zp-keys/src/sovereignty/mod.rs

/// Load the Genesis secret for this process.
///
/// On first call, reads `genesis.json` from `ZP_HOME/` to determine the
/// sovereignty mode, invokes the corresponding provider, and caches the result
/// in a process-scoped `OnceLock`. Subsequent calls return the cached value
/// without touching the credential store.
///
/// Returns a reference into the static cache — the secret lives for the
/// process lifetime. `mlockall` (if applied in main()) prevents swap exposure.
///
/// Callers MUST NOT call credential-store APIs directly. All sovereign-root
/// access goes through this function.
pub fn load_sovereign_root(genesis_record_path: &Path) -> Result<&'static [u8; 32], KeyError> {
    static CACHED: OnceLock<Result<[u8; 32], String>> = OnceLock::new();
    let result = CACHED.get_or_init(|| {
        load_sovereign_root_uncached(genesis_record_path)
            .map_err(|e| format!("{}", e))
    });
    match result {
        Ok(s) => Ok(s),
        Err(msg) => {
            let already_cached = CACHED.get().is_some();
            if already_cached {
                Err(KeyError::CredentialStore(
                    "Sovereignty authentication failed earlier — re-run to retry.".into()
                ))
            } else {
                Err(KeyError::CredentialStore(msg.clone()))
            }
        }
    }
}

fn load_sovereign_root_uncached(genesis_record_path: &Path) -> Result<[u8; 32], KeyError> {
    // Fast path: standard OS Keychain. Covers Touch ID, login-password,
    // and file-based modes (all write the standard Keychain during enrollment).
    // Hardware wallets (Trezor, YubiKey) don't write the standard Keychain,
    // so this fails fast and falls through.
    if let Some(home_dir) = genesis_record_path.parent() {
        if let Ok(keyring) = Keyring::open(home_dir.join("keys")) {
            if let Ok((secret, _)) = keyring.load_genesis_secret() {
                return Ok(secret);
            }
        }
    }
    // Sovereignty-provider path: hardware wallets and any mode where
    // the standard Keychain doesn't hold the secret.
    let provider = provider_for_genesis_record(genesis_record_path)?;
    provider.load_secret()
}
```

**Why `&'static [u8; 32]` not `Zeroizing<[u8; 32]>`:** OnceLock holds the
value for process lifetime by design. A `Zeroizing` wrapper dropped at
end-of-scope would conflict with the static lifetime. The process exits anyway;
`mlockall()` (separate mitigation, not gated on this work) prevents swap
exposure. Document this choice explicitly; do not try to work around it with
`Arc<Mutex<Option<Zeroizing<[u8;32]>>>>`.

**How `Keyring::load_genesis_secret()` relates:** `load_genesis_secret()` in
keyring.rs remains the Keyring-struct method that the fast path uses. The
canonical public API for external callers is `load_sovereign_root()`, not
`load_genesis_secret()`. `load_genesis_secret()` becomes an implementation
detail of the fast path inside `load_sovereign_root_uncached()`.

**`provider_for_genesis_record()`:** Reads `sovereignty_mode` from `genesis.json`
and returns the appropriate `Box<dyn SovereigntyProvider>`. Already effectively
exists in `zp-server/src/lib.rs:308–317` — extract into sovereignty/mod.rs as a
shared helper. This removes the server lib's direct dependency on sovereignty
internals (addressing violation 3 in the call-site catalog).

---

## 3 · Migration plan — `zeropoint` / `vault-master-key` (relic)

**Code changes:** none. The current code never writes or reads this entry.

**Operator action:** `zp keychain cleanup` (new command, item 8 details the
interface) deletes the orphan entry after operator review and confirmation.

**Risk:** zero. The entry is not referenced anywhere.

---

## 4 · Migration plan — `zeropoint-operator` / `operator-secret`

### Code change (small, targeted)

Remove the best-effort write from `save_operator()` in `keyring.rs:422`:

```rust
// BEFORE
let _ = save_operator_to_credential_store(&secret);

// AFTER — deleted; canonical store is operator.secret.enc
```

Remove `load_operator_from_credential_store()` (`keyring.rs:710–738`) entirely
— it is dead code and its presence is a violation precedent.

Remove `save_operator_to_credential_store()` (`keyring.rs:688–706`) entirely —
no longer called.

### No data migration required

The canonical operator secret store is already `operator.secret.enc`. Every
operator has this file (it is always written by `save_operator()`). The Keychain
entry is a redundant cache that was never read back.

Deleting the write means: next `zp init` (or re-enrollment) does not create a
new `zeropoint-operator` entry. The existing entry on APOLLO stays in place until
`zp keychain cleanup` removes it.

### Operator action

`zp keychain cleanup` lists all orphan entries (`zeropoint-operator`,
`zeropoint`) and asks for confirmation before deleting. Auto-delete is too
aggressive — operators should see what is being removed.

---

## 5 · Discipline pin spec

### What the pin forbids

```
discipline: singular_sovereign_root

  Direct credential-store reads are forbidden outside
  crates/zp-keys/src/sovereignty/. All consumers must use
  zp_keys::sovereignty::load_sovereign_root() or the derived
  helpers (vault_key::resolve_vault_key, audit_signer_seed, etc.)

  Forbidden patterns:
    - keyring::Entry::get_password() outside crates/zp-keys/src/sovereignty/
      or crates/zp-keys/src/keyring.rs
    - keyring::Entry::set_password() outside crates/zp-keys/src/sovereignty/
      or crates/zp-keys/src/keyring.rs (one write site: genesis enrollment)
    - SecItemCopyMatching outside crates/zp-keys/src/sovereignty/touchid.rs
    - SecItemAdd outside crates/zp-keys/src/sovereignty/touchid.rs
    - SecItemDelete outside crates/zp-keys/src/sovereignty/touchid.rs
    - provider.load_secret() outside crates/zp-keys/src/sovereignty/ and
      crates/zp-server/src/lib.rs (pending full migration; narrow the
      exception list as call sites are collapsed)

  Enforcement: zp-discipline AST scan (same mechanism as existing pins),
  CI-failing on violation.
```

### Where the pin lives

`docs/DISCIPLINE-PINS.md` (alongside existing pins). Scan runs as part of
`cargo xtask discipline` or the CI discipline step.

### AST scan approach

The scan checks `use` statements and direct function calls:
- Scan all `.rs` files outside `crates/zp-keys/src/sovereignty/` and
  `crates/zp-keys/src/keyring.rs`
- Flag: any `keyring::Entry` usage
- Flag: any `SecItemCopyMatching|SecItemAdd|SecItemDelete` literal
- Flag: any `.load_secret()` call on a variable typed as `dyn SovereigntyProvider`
  outside the two allowed modules

Implementation: grep-based initially (consistent with existing discipline
pins); graduate to syn-based AST scan if false-positive rate is high.

### Tests covering the contract

```rust
// crates/zp-keys/src/sovereignty/mod.rs (test module)

#[test]
fn load_sovereign_root_calls_provider_at_most_once() {
    // Uses test-support mock keyring (Seam 11) plus a counting mock provider
    let call_count = Arc::new(AtomicU32::new(0));
    // ... install mock, call load_sovereign_root() 5 times ...
    assert_eq!(call_count.load(Ordering::Relaxed), 1);
}

#[test]
fn load_sovereign_root_cached_error_returns_actionable_message() {
    // First call fails; subsequent calls return the "re-run" message
}
```

---

## 6 · Integration test plan

```rust
// crates/zp-cli/tests/exec_keychain_count.rs

/// Simulates the full `zp configure exec` flow under a mock credential store.
/// Asserts that the mock's read-count is exactly 1 for the standard Keychain
/// path and 0 for the sovereignty-provider path (standard Keychain fast path
/// succeeds).
#[test]
fn configure_exec_standard_path_reads_keychain_once() {
    let mock = MockKeyring::new_with_genesis([0x42u8; 32]);
    let vault = build_test_vault(&mock);
    let (count_before, count_after) = run_configure_exec_under_mock(&mock, &vault);
    assert_eq!(count_after - count_before, 1,
        "expected exactly 1 credential-store read; got {}",
        count_after - count_before);
}

/// Same test for server's audit-signer path via Fix C fast path.
#[test]
fn server_audit_signer_hits_cache_not_provider() {
    let mock = MockKeyring::new_with_genesis([0x42u8; 32]);
    let provider_call_count = Arc::new(AtomicU32::new(0));
    run_app_state_init_under_mock(&mock, provider_call_count.clone());
    assert_eq!(provider_call_count.load(Ordering::Relaxed), 0,
        "server audit-signer must use cached genesis, not call sovereignty provider");
}
```

**Mock infrastructure:** The test-support feature (`zp-keys/Cargo.toml:test-support`)
already installs an in-memory mock keyring (Seam 11, `docs/STRUCTURAL-AUDIT-2026-05.md`).
The counting mock provider needs to be added as a test double in the same
feature gate.

---

## 7 · Risk surface

| Risk | Severity | Notes |
|------|----------|-------|
| Removing `save_operator_to_credential_store()` | **Zero** | Write is best-effort; silently ignored on failure already; canonical store is the encrypted file |
| Removing `load_operator_from_credential_store()` | **Zero** | Dead code; not callable from outside the module |
| Introducing `load_sovereign_root()` | **Low** | New API; callers currently using `keyring.load_genesis_secret()` must be migrated. Risk: if `genesis.json` doesn't exist (pre-onboarding state), `load_sovereign_root_uncached()` must fail cleanly without panicking |
| Migrating call sites from `load_genesis_secret()` to `load_sovereign_root()` | **Medium** | `load_genesis_secret()` takes `&self` on Keyring; `load_sovereign_root()` takes a path and is a free function. Callers that construct Keyring first need to pass the genesis record path instead. Audit each migration site individually |
| `zp keychain cleanup` command | **Low** | Explicit operator confirmation before deletion; no auto-delete |
| Older `vault.json` files | **Zero** | The vault format is unchanged. Vault key derivation is unchanged (`BLAKE3(genesis, context)`). Vaults opened with the new code are decryptable; vaults opened with the old code remain decryptable |
| Multi-machine setups (APOLLO + ARTEMIS) | **Low** | Each machine has its own Keychain; the `zeropoint-operator` entry is per-machine. Removing the write means new machines won't create the operator Keychain entry (correct). Existing entries cleaned up per machine via `zp keychain cleanup` |
| Audit chains signed with the current operator key | **Zero** | The operator key itself is unchanged; only where it's cached changes. The audit chain remains valid |
| Server lib's direct `provider.load_secret()` calls | **Low** | Fix C already added the fast path. The sovereignty-provider fallback remains for hardware wallets; it's contained and correct. Full migration (moving provider invocation into `load_sovereign_root()`) is a subsequent step after the API is established |

---

## 8 · Sequencing

Dependencies flow in this order:

```
Step 1 (smallest, biggest impact — ship first)
  Remove save_operator_to_credential_store() from save_operator()
  Remove load_operator_from_credential_store() dead code
  Files: crates/zp-keys/src/keyring.rs

Step 2 (foundation for everything else)
  Add load_sovereign_root() + load_sovereign_root_uncached() to sovereignty/mod.rs
  Extract provider_for_genesis_record() helper from zp-server/src/lib.rs
  Files: crates/zp-keys/src/sovereignty/mod.rs

Step 3 (migrate call sites)
  Replace direct load_genesis_secret() / load_genesis_from_credential_store()
  calls in zp-server/src/lib.rs with load_sovereign_root()
  Replace in zp-cli/src/main.rs (three resolve_vault_key() call sites already
  go through the standard-Keychain fast path; confirm they still work through
  the new API)
  Files: crates/zp-server/src/lib.rs, crates/zp-cli/src/main.rs

Step 4 (cleanup command)
  Add `zp keychain cleanup` subcommand:
    - Lists orphan entries (zeropoint, zeropoint-operator)
    - Shows creation date and what the entry was for
    - Deletes only on explicit confirmation
  Files: crates/zp-cli/src/main.rs, new crates/zp-cli/src/keychain.rs

Step 5 (pin and tests)
  Add singular_sovereign_root discipline pin to docs/DISCIPLINE-PINS.md
  Add integration tests (mock provider, assert call count == 1)
  Files: docs/DISCIPLINE-PINS.md, crates/zp-keys/src/sovereignty/mod.rs (tests)

Step 6 (architecture)
  Update docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md with implementation refs
  Fold into ARCHITECTURE-2026-05.md as section II.21
```

**Steps 1 and 2 are independent and can ship together in one commit.**
Step 3 is gated on Step 2. Step 4 can ship any time after Step 1. Step 5
is gated on Steps 2–3. Step 6 is always last.

**Step 1 alone** eliminates the vestigial `zeropoint-operator` Keychain write
and immediately reduces ACL grants by one for workflows that call `save_operator()`
(re-enrollment, `zp init`). The two-process minimum (server + configure exec)
is irreducible and correct; "Always Allow" on both entries eliminates them for
subsequent builds.

---

## Open questions for review

1. **`load_sovereign_root()` path argument.** The function needs the
   `genesis.json` path to determine the sovereignty mode. Should it read
   `ZP_HOME` from environment directly, or require the caller to pass the path?
   Caller-passes is more testable; env-read is simpler for callers. Current
   practice in the codebase (e.g., `resolve_zp_home()` in commands.rs) passes
   the resolved path. Recommend: caller-passes.

2. **`Keyring::load_genesis_secret()` visibility after migration.** Once the
   canonical API is `load_sovereign_root()`, should `load_genesis_secret()` be
   made `pub(crate)` to prevent external callers from bypassing the canonical
   path? This would make the discipline pin mechanical rather than just
   grep-based for that specific call site. Recommend: yes, tighten visibility
   in Step 3.

3. **Server lib's remaining `provider.load_secret()` calls.** Fix C
   fast-pathed the standard-Keychain case; the hardware-wallet fallback in
   `load_genesis_secret_from_provider()` still calls the provider directly.
   Full migration into `load_sovereign_root()` would remove the server's
   dependency on provider internals entirely. Recommend: migrate in Step 3;
   server lib should not know how to read genesis.json and invoke providers
   independently.

---

## Refs

- `docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md` — architectural note this implements
- `docs/handoffs/vault-session-scoped-reads-design-2026-05.md` — precedent (§8 has the instrumentation findings that led here)
- `crates/zp-keys/src/keyring.rs` — all `keyring::Entry` call sites
- `crates/zp-keys/src/sovereignty/touchid.rs` — `secure_keychain` module
- `crates/zp-server/src/lib.rs:262–329` — `load_operator_via_sovereignty_provider`, `load_genesis_secret_from_provider`
- Task #152 — this work
- Task #91 — hardening pass this belongs to
- Architecture II.0 — contracts singular, implementations plural (parent principle)
