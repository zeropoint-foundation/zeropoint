# Key rotation runbook

**Audience:** Operators running `zp-server` who need to rotate keys
after a compromise, scheduled policy, or device migration.
**Prereqs:** Shell access to the host, `zp` CLI on `PATH`, access to the
OS credential store (macOS Keychain / Linux Secret Service / Windows
Credential Manager).
**Reference:** `docs/ARCHITECTURE-2026-04.md` §2 for the trust hierarchy,
`crates/zp-keys/src/rotation.rs` for the rotation certificate format.

## Key hierarchy

ZeroPoint uses a three-tier Ed25519 key hierarchy:

    Genesis (root of trust, self-signed)
      └── Operator (signed by Genesis)
            └── Agent (signed by Operator)

Each tier has a signing secret and a certificate. The vault key is
derived deterministically from the Genesis secret via BLAKE3 and is
used to encrypt all subordinate secrets at rest (ChaCha20-Poly1305).

### Storage locations

| Key             | Secret storage                          | Certificate             |
|-----------------|-----------------------------------------|-------------------------|
| Genesis         | OS credential store (`zeropoint-genesis`) | `~/.zeropoint/keys/genesis.json` |
| Operator        | `operator.secret.enc` (vault-encrypted) | `~/.zeropoint/keys/operator.json` |
| Agent           | `<agent>.secret.enc` (vault-encrypted)  | `~/.zeropoint/keys/<agent>.json` |
| Vault key       | Derived at runtime (never stored)       | N/A                     |

Plaintext `.secret` files are forbidden. The server refuses to start if
any are found (canon permission enforcement).

## 1. Genesis key recovery (no rotation)

Genesis keys are not rotated — they are recovered. If you have the
24-word mnemonic from the original ceremony:

```
zp recover
```

This prompts for the 24 words, verifies the mnemonic produces the
expected public key (from `genesis.json`), then re-seals the secret
to the OS credential store. If a secret already exists in the store,
you'll be asked to confirm the overwrite (after verification, not before).

After recovery, restart `zp-server` so the vault key cache is refreshed:

```
zp serve          # or however the server is managed
```

The vault key is derived from the Genesis secret and cached once at
startup. A stale cache means the server cannot decrypt operator or
agent secrets.

## 2. Operator key rotation

### 2.1 CLI rotation command

```
zp keys rotate --target operator --reason "scheduled rotation"
```

This command:

1. Loads the Genesis key from the OS credential store (needed for
   co-signing and vault key derivation).
2. Loads the current operator key (decrypted via vault key).
3. Generates a new Ed25519 operator keypair, certified by Genesis.
4. Issues a rotation certificate signed by the old operator key.
5. Genesis co-signs the rotation certificate (defense-in-depth).
6. Saves the new operator key encrypted under the vault key
   (`operator.secret.enc`).
7. Persists the rotation certificate to
   `~/.zeropoint/keys/rotations.json`.

The command prompts for confirmation before proceeding. Pipe `echo y`
for non-interactive use.

### 2.2 Post-rotation steps

After running `zp keys rotate --target operator`:

1. **Restart the server.** The vault key cache and session tokens are
   stale.

   ```
   # Stop the running server, then:
   zp serve
   ```

2. **Verify the rotation:**

   ```
   zp keys list
   ```

3. **Note:** Agent keys signed by the old operator remain valid. The
   rotation chain preserves identity continuity — verifiers walk the
   chain to resolve old key references.

### 2.3 Manual rotation (library-level)

If the CLI command is unavailable, the rotation can be performed
directly against the `zp-keys` library:

1. Load the old operator `SigningKey` and Genesis `SigningKey`.
2. Call `RotationCertificate::issue(old_key, new_pub, KeyRole::Operator, sequence, prev_hash, reason)`.
3. Call `cert.co_sign(&genesis_signing_key)`.
4. Save the new operator key with `keyring.save_operator_with_genesis_secret()`.
5. Persist the rotation certificate to `rotations.json`.

### 2.3 What changes on rotation

| Artifact                 | Changes? | Why                                        |
|--------------------------|----------|--------------------------------------------|
| `operator.secret.enc`    | Yes      | New secret, re-encrypted under vault key   |
| `operator.json`          | Yes      | New certificate (signed by Genesis)        |
| Vault key                | No       | Derived from Genesis, which hasn't changed |
| Session tokens           | Yes      | Derived from operator Ed25519 key (HMAC)   |
| Agent certificates       | Maybe    | If issuer field references operator pubkey  |
| `genesis.json`           | No       | Genesis is unchanged                       |

**Important:** All active browser sessions will be invalidated on
operator rotation because session tokens are HMAC-derived from the
operator's Ed25519 key. Users will need to re-authenticate.

## 3. Vault key implications

The vault key is deterministic: same Genesis secret always produces the
same vault key (`BLAKE3-keyed(genesis_secret, "zp-credential-vault-v1")`).

This means:

- **Genesis recovery** does not change the vault key (same secret → same
  derived key → existing encrypted secrets still decrypt).
- **Genesis rotation** (if ever implemented) *would* change the vault key,
  requiring re-encryption of all vault-encrypted secrets. This is a
  breaking operation and is intentionally not supported in v0.1.

## 4. Emergency procedures

### 4.1 Compromised operator key

1. Stop the server immediately.
2. Rotate the operator key (§2.2).
3. Audit the chain: `zp audit verify` — look for unauthorized entries
   during the compromise window.
4. Restart with the new key.
5. All agents will need their sessions re-established.

### 4.2 Compromised Genesis secret

This is the worst case. The Genesis key is the root of trust.

1. Stop the server.
2. If you have the 24-word mnemonic, the attacker may also have it.
   Assume all derived keys are compromised.
3. A full re-ceremony (`zp init`) is required on a clean machine.
4. All operator and agent keys must be re-issued.
5. The audit chain should be archived and a new chain started with the
   new Genesis key.
6. Credential vault contents (API keys, tokens) are compromised and
   must be rotated at the provider level.

### 4.3 Lost credential store access

If the OS credential store is inaccessible (e.g., corrupted Keychain,
new machine) but you have the 24-word mnemonic:

```
zp recover
```

This re-seals the Genesis secret to the new credential store. The vault
key is re-derived identically, so encrypted secrets are still accessible.

If the mnemonic is also lost, the deployment is unrecoverable. This is
by design — sovereignty means no backdoor.

## 5. Planned improvements

- Server-side rotation endpoint for hot rotation without full restart
- Mesh-aware rotation propagation (for multi-node deployments)
- Automated agent key re-issuance after operator rotation
- Rotation chain integrity verification command (`zp keys verify-chain`)
