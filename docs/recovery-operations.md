# Recovery operations

**Audience:** Operators who need to restore access to a ZeroPoint
deployment after losing credential store access (new machine, corrupted
Keychain, OS reinstall).
**Prereqs:** The 24-word mnemonic from the original Genesis ceremony,
`zp` CLI on `PATH`, `~/.zeropoint/keys/genesis.json` intact on disk.

## Overview

ZeroPoint's sovereignty model means there is no server-side password
reset, no admin backdoor, and no recovery without the mnemonic. The
24-word recovery kit is the only path back to a deployment whose
credential store is lost.

The recovery pipeline:

    24 words → BIP-39 decode → Ed25519 secret (32 bytes)
            → verify against genesis.json public key
            → re-seal to OS credential store
            → derive vault key (BLAKE3)
            → decrypt operator.secret.enc
            → system operational

## 1. Prerequisites check

Before running recovery, confirm:

- `~/.zeropoint/keys/genesis.json` exists and is readable. This file
  contains the Genesis certificate with the public key that your mnemonic
  must match. If this file is gone, recovery is not possible — you need
  a fresh `zp init`.

- You have all 24 words, in order. Partial mnemonics cannot be used.
  The 24th word includes a checksum that validates the entire sequence.

- The OS credential store is accessible (you can write to it). On macOS,
  this means the login Keychain is unlocked. On Linux, the Secret Service
  daemon (e.g., gnome-keyring) must be running.

## 2. Running recovery

```
zp recover
```

The command will:

1. **Load genesis.json** and extract the public key (hex-encoded).
2. **Prompt for 24 words.** Enter them space-separated on one line, or
   one per line (terminate with a blank line). Input is from stdin, so
   piping works: `echo "word1 word2 ... word24" | zp recover`.
3. **Verify the mnemonic.** The words are BIP-39 decoded to a 32-byte
   secret, then the corresponding Ed25519 public key is computed and
   compared against the genesis certificate. If they don't match, the
   command exits with an error. No changes are made.
4. **Check for existing secret.** If the credential store already has a
   genesis secret, you're asked to confirm overwrite. This prompt comes
   *after* mnemonic verification — wrong words are rejected before you're
   asked to overwrite anything.
5. **Re-seal the secret.** The verified secret is written to the OS
   credential store (service: `zeropoint-genesis`, account:
   `genesis-secret`).
6. **Verify operator key unlock.** The vault key is derived from the
   re-sealed Genesis secret and used to decrypt `operator.secret.enc`.
   If this succeeds, the system is fully operational.

## 3. Post-recovery

After successful recovery:

```
zp serve
```

The server will cache the vault key from the credential store at startup
and resume normal operation. All existing encrypted credentials (vault,
operator, agent secrets) are accessible because the vault key is
deterministic — same Genesis secret produces the same vault key.

No re-onboarding is needed. The onboard page will redirect to the
dashboard because `genesis.json` exists and the server detects a
completed ceremony.

## 4. Mnemonic handling

### Generation

The mnemonic is generated during `zp init` (Genesis ceremony):

- 256 bits of cryptographic randomness (from OS CSPRNG)
- SHA-256 checksum: first 8 bits appended → 264 bits total
- Split into 24 × 11-bit indices into the BIP-39 English wordlist
  (2048 words)
- Displayed once during onboarding as a "Recovery Kit"

### Derivation (mnemonic → keypair)

ZeroPoint uses direct Ed25519 derivation, *not* BIP-32/BIP-44 HD paths:

```
mnemonic → BIP-39 decode → 32-byte secret
         → ed25519_dalek::SigningKey::from_bytes(&secret)
         → public key = signing_key.verifying_key()
```

This is simpler than cryptocurrency wallet derivation and means there
are no derivation paths, no passphrase, and no ambiguity — one mnemonic
maps to exactly one keypair.

### Storage recommendations

The mnemonic should be:

- Written on paper (or stamped on metal) and stored in a physically
  secure location (safe, safety deposit box).
- Never stored digitally on any device that has network access.
- Never photographed (cameras sync to cloud).
- Never emailed, messaged, or entered into any form other than `zp recover`.

If the mnemonic is compromised, assume the Genesis key is compromised.
See `docs/key-rotation-runbook.md` §4.2 for the response procedure.

## 5. Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| "genesis.json not found" | Missing certificate file | Cannot recover. Run `zp init` for fresh ceremony. |
| "does not produce the expected genesis keypair" | Wrong words or wrong order | Check for typos. Verify you have the correct mnemonic for this deployment. |
| "Failed to write genesis secret" | Credential store inaccessible | Unlock the Keychain (macOS) or start the Secret Service daemon (Linux). |
| "Could not decrypt operator key" | operator.secret.enc corrupted or wrong vault key | If `zp recover` succeeded but operator decrypt fails, the enc file may be from a different Genesis. |
| Recovery succeeds but server won't start | Stale vault key cache | The server caches the vault key at startup. If it was running during recovery, restart it. |

## 6. Implementation reference

| Component | File | Key function |
|-----------|------|-------------|
| BIP-39 encode/decode | `crates/zp-keys/src/recovery.rs` | `encode_mnemonic()`, `decode_mnemonic()` |
| Mnemonic verification | `crates/zp-keys/src/recovery.rs` | `verify_recovery()` |
| CLI orchestration | `crates/zp-cli/src/recover.rs` | `run()` |
| Credential store | `crates/zp-keys/src/keyring.rs` | `save_genesis_to_credential_store()` |
| Vault key derivation | `crates/zp-keys/src/vault_key.rs` | `derive_vault_key()` |
| Genesis key reconstruction | `crates/zp-keys/src/hierarchy.rs` | `GenesisKey::from_parts()` |
