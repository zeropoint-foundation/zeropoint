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

### 2.1 Current state (v0.1)

The rotation certificate format and chain validation are implemented in
`zp-keys::rotation`:

- `RotationCertificate::issue()` — creates a rotation cert signed by the
  old key, proving possession.
- `RotationCertificate::co_sign()` — Genesis co-signs for defense-in-depth.
- `RotationChain::register()` — validates sequence continuity and
  registers the cert.
- `RotationChain::resolve_current()` — maps any historical key to the
  current active key.

**Not yet wired:** There is no `zp rotate` CLI command or HTTP endpoint.
Operator rotation currently requires manual use of the library API.

### 2.2 Manual operator rotation procedure

Until `zp rotate` is implemented, the procedure is:

1. **Stop the server.** The vault key cache must be invalidated.

2. **Generate a new operator keypair** using the zp-keys library.
   The new key must be signed by the Genesis key (via hierarchy).

3. **Issue a rotation certificate:**
   - Old operator key signs the rotation cert.
   - Genesis key co-signs for defense-in-depth.
   - Register the cert in the rotation chain.

4. **Re-encrypt the new operator secret** under the vault key and write
   it to `operator.secret.enc`. Remove the old encrypted secret.

5. **Update any agent keys** that reference the old operator public key
   in their certificates' issuer field.

6. **Restart the server.** The new operator key will be loaded from the
   updated encrypted secret.

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

- `zp rotate operator` — CLI command to automate §2.2
- `zp rotate agent <name>` — per-agent key rotation
- Rotation chain persistence to `~/.zeropoint/keys/rotation-chain.json`
- Server-side rotation endpoint for hot rotation without full restart
- Mesh-aware rotation propagation (for multi-node deployments)
