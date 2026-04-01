# Genesis Onboarding UX — Design Notes

> "It starts with the Genesis, biometrics, hardware wallets, and what needs to feel like the natural way things should be done on the Agentic Internet." — Ken, 2026-03-21

## The Problem

Every AI tool today asks the same question: "paste your API key here." This is 2024-era friction ported forward. It doesn't scale. A single operator running 5 tools needs to manage 20-40 credentials manually, one `.env` at a time, with no governance, no audit trail, no cost visibility, and no revocation path.

ZeroPoint already solves the plumbing (ConfigEngine, CredentialVault, API proxy, receipt chain). What's missing is the front door — the moment a new user goes from zero to governed in under 60 seconds.

## The Vision: `zp genesis`

One command. One ceremony. Everything after flows from it.

```
$ zp genesis

  ZeroPoint Genesis
  ─────────────────

  This creates your cryptographic root of trust.
  Everything in ZeroPoint derives from this key.

  Choose your key source:

  [1] Biometric (Face / Fingerprint)     ← recommended
  [2] Hardware wallet (Trezor / Ledger)
  [3] Generate new (software key)

  > 1

  Position your face for the camera...
  ✓ Biometric embedding captured (128-dim, zero-storage)
  ✓ Genesis key derived (Ed25519, BLAKE3)
  ✓ Operator certificate issued
  ✓ Vault key derived and cached (Keychain)
  ✓ Constitutional bedrock sealed (5 gates)

  Your identity: 7eb8da3f...

  You're ready. Run `zp scan` to discover your AI tools.
```

### What just happened (invisible to user):
1. Biometric embedding → BLAKE3 → Ed25519 Genesis key (using existing `genesis-biometric` WASM module, adapted for CLI)
2. Genesis → Operator → certificate chain written to `~/.zeropoint/keys/`
3. Vault master key derived from Genesis via BLAKE3 keyed hash
4. Vault key cached in OS credential store (Keychain on macOS)
5. Constitutional bedrock hash sealed into genesis record
6. `zeropoint.toml` written with sane defaults

### For hardware wallet users:
```
  Connect your Trezor and confirm on device...
  ✓ Trezor signed derivation challenge
  ✓ Genesis key derived from hardware signature
  ...same flow continues...
```

## Phase 2: Credential Onboarding

Immediately after Genesis, guide the user through credential loading:

```
$ zp scan

  Discovered 5 AI tools in ~/projects:

  Tool          Status    Missing
  ─────────────────────────────────────
  OpenMAIC      ⚠ 2/26   openai/api_key, anthropic/api_key
  PentAGI       ⚠ 3/37   openai/api_key, anthropic/api_key, google/api_key
  IronClaw      ⚠ 1/8    hedera/operator_key
  Agent-Zero    ✓ ready   (all from defaults)
  LocalAI       ✓ ready   (no API keys needed)

  Run `zp onboard` to add your API keys interactively.
```

```
$ zp onboard

  Let's set up your credentials. Each key is stored encrypted
  in your vault, derived from your Genesis identity.

  ┌─ OpenAI ──────────────────────────────────┐
  │ Get your key: https://platform.openai.com │
  │ API Key: sk-••••••••••••••••••••••••••••   │
  │ ✓ Stored: openai/api_key (encrypted)      │
  └───────────────────────────────────────────┘

  ┌─ Anthropic ───────────────────────────────┐
  │ Get your key: https://console.anthropic.com│
  │ API Key: sk-ant-•••••••••••••••••••••••••  │
  │ ✓ Stored: anthropic/api_key (encrypted)   │
  └───────────────────────────────────────────┘

  2 credentials stored. 4 tools now configurable.

  Enable governance proxy? [Y/n] y
  ✓ Proxy enabled on :3000
  ✓ All tool configs rewritten to route through ZP

  Done. Your tools are governed.
```

## Phase 3: The Governed Steady State

After onboarding, the user's daily flow is invisible:

- Tools call LLM APIs → requests route through ZP proxy
- Every call: policy check → forward → receipt → audit
- `zp status` shows live cost, token usage, policy decisions
- `zp audit log` shows the full hash-chained trail
- Re-authentication: Keychain unlock (login password now; Touch ID in v0.2)

## Key Design Principles

### 1. Single Root of Trust
Everything derives from one secret. Biometric → Genesis → Operator → Agent → Vault key. Lose nothing, remember nothing. Your face/fingerprint/hardware IS your credential.

### 2. Progressive Disclosure
- `zp genesis` — just works with recommended defaults
- `zp genesis --wizard` — shows every choice
- `zp genesis --hardware` — Trezor/Ledger path
- Advanced users can `zp keys issue`, `zp policy load`, etc.

### 3. Zero Friction ≠ Zero Security
The fastest path is also the most secure path. Biometric derivation is both easier AND stronger than env vars. The proxy is both more convenient (one-time setup) AND gives you governance. Security and UX are aligned, not traded off.

### 4. Works Offline, Scales to Mesh
Genesis ceremony is fully local. No network required. But the same identity works on the mesh — peers verify your certificate chain, not a central authority.

### 5. Credential Portability
`zp vault export --encrypted` creates a portable vault backup.
`zp vault import` on a new machine + biometric re-derivation = instant migration.
Hardware wallet users: plug in on any machine, derive, done.

## UX Gaps (Credential Store Integration)

The move to OS credential store in v0.1 introduced several UX surfaces that need design attention:

### 1. System Prompt Surprise (macOS)
The first Keychain write triggers a macOS system dialog: *"zp wants to use your confidential information stored in 'zeropoint-genesis' in your keychain."* The user is looking at their terminal; a modal steals focus.
**Mitigation (v0.1 — done):** `zp init` now prints a heads-up line before the Keychain write: *"Your system may ask permission to access the keychain — click Allow"*

### 2. Every Configure Invocation Reads Keychain
Vault key derivation is on-demand, so `zp configure scan`, `tool`, `auto`, `vault-add`, and `providers` all trigger a Keychain read. After "Always Allow" this is transparent, but a one-time "Allow" means re-prompting. Keychain lock state (sleep, screen lock) can also trigger re-prompts.
**Future:** Consider a short-lived session cache (e.g. derive once, hold in memory for the duration of a multi-step `zp configure auto` run). Not a disk cache — just process lifetime.

### 3. Linux Secret Service Requirements
`sync-secret-service` requires D-Bus + a secret service daemon (GNOME Keyring, KDE Wallet). Headless servers, Docker containers, and minimal distros won't have this. Error messages are often opaque D-Bus errors.
**Mitigation (v0.1 — done):** Platform-specific error guidance in `zp configure` error handler. Points to `apt install gnome-keyring` or `SECRETS_MASTER_KEY` fallback for CI/headless.
**Future:** Consider `keyctl` (Linux kernel keyring) as a lighter alternative for headless systems.

### 4. Silent Migration
Existing users with `genesis.secret` on disk will have their file migrated (3-pass overwrite + delete) on next load. A file they expect to exist just disappears.
**Mitigation (v0.1 — done):** Migration now prints a visible notification: *"✓ Genesis secret migrated to OS credential store (genesis.secret removed from disk)"*

### 5. Honest Security Claims
`zp init` previously always said "never on disk" and "sealed in OS credential store" even when credential store was unavailable. The current protection level is login-password Keychain (macOS) or session-unlocked Secret Service (Linux) — NOT biometric gating.
**Mitigation (v0.1 — done):** Output now names the specific platform mechanism and makes no Touch ID claims. File fallback states clearly where the secret lives.
**Future (v0.2):** Touch ID via `SecAccessControlCreateFlags::biometryCurrentSet`, requires code-signed binary.

### 6. Keychain Denial Recovery
If a user clicks "Deny" on the macOS Keychain prompt, the save silently falls back to file. But on subsequent access, they might "Always Allow" — now they have the secret in BOTH places. The load prefers credential store, and migration logic would try to delete the file, but the timing may confuse users.
**Future:** `zp doctor` command that audits key state: checks credential store, checks for orphan files, reports clearly.

## Implementation Roadmap

### Now (v0.1 — done)
- [x] Genesis key generation (`zp init`)
- [x] Key hierarchy (Genesis → Operator → Agent)
- [x] CredentialVault (ChaCha20-Poly1305)
- [x] ConfigEngine (semantic sed, 60+ patterns)
- [x] Scan + Auto discovery
- [x] API proxy with governance, metering, receipts
- [x] Vault key derivation from Genesis (BLAKE3)
- [x] Genesis secret in OS credential store (Keychain) — never on disk
- [x] Legacy migration: auto-moves genesis.secret from disk to Keychain
- [x] On-demand vault key derivation (no cache layer)
- [x] Zeroization of all key material in memory
- [x] Keychain prompt warning in `zp init` (pre-dialog heads-up)
- [x] Visible migration notification (no silent file deletion)
- [x] Platform-specific error guidance (macOS Keychain / Linux Secret Service / headless)
- [x] Honest security claims (names actual protection mechanism per platform)
- [x] Runtime source tracking in vault key resolution
- [x] Env var entropy validation (reject short/weak SECRETS_MASTER_KEY)
- [x] Multi-pass secure file deletion during migration

### Next (v0.2)
- [ ] `zp genesis` unified command (replaces `zp init`)
- [ ] `zp onboard` interactive credential wizard
- [ ] `zp doctor` — key state audit (credential store, orphan files, integrity check)
- [ ] Touch ID via `security-framework` (`SecAccessControlCreateFlags::biometryCurrentSet`)
- [ ] Code-sign `zp` binary for biometric Keychain access
- [ ] Trezor integration (`trezor-client` crate, sign-to-derive)
- [ ] CLI biometric via `genesis-biometric` WASM (camera → embedding → key)
- [ ] `zp vault export/import` for machine migration
- [ ] Linux `keyctl` backend for headless/Docker environments (no D-Bus needed)
- [ ] Session-scoped vault key cache (process lifetime only, no disk)

### Future (v0.3+)
- [ ] Ledger hardware wallet support
- [ ] Passkey / WebAuthn integration for browser-based flows
- [ ] Multi-operator key ceremony (threshold signatures)
- [ ] Vault key rotation with automatic re-encryption
- [ ] Mobile companion app (biometric on phone, key on desktop)
- [ ] `zp genesis --recover` from biometric re-enrollment

## Security Architecture

```
Biometric Embedding (128-dim facial)   OR   Trezor Hardware Wallet
    │                                            │
    ▼                                            ▼
BLAKE3-keyed(embedding, "zp-genesis-v1")    Sign("zp-genesis-derive-v1")
    │                                            │
    └──────────────────┬─────────────────────────┘
                       ▼
            Ed25519 Genesis Key (root of trust)
                       │
                       ▼
            OS Credential Store (Keychain / Secret Service)
            ┌──────────────────────────────────────────┐
            │  Genesis secret: NEVER on disk.           │
            │  Protected by platform security.          │
            │  Future: biometryCurrentSet via           │
            │  SecAccessControl (code-signed binary).   │
            └──────────┬───────────────────────────────┘
                       │
          ┌────────────┼────────────────┐
          ▼            ▼                ▼
    BLAKE3-keyed   Certificate      Agent Keys
    (vault-v1)     Chain            (Operator → Agent)
          │
          ▼
    Vault Key (ephemeral, zeroized after use)
          │
          ▼
    ChaCha20-Poly1305 → Encrypted Credentials
```

### Trust Properties
- **Single secret**: Genesis key is the only root. Everything else derived.
- **No storage of biometrics**: Embeddings processed in WASM, never persisted.
- **Hardware isolation**: Trezor path keeps Genesis secret on tamper-resistant chip.
- **Zeroize on drop**: All key material in memory is overwritten when no longer needed.
- **Atomic persistence**: Vault writes use tmp+rename for crash safety.
- **Hash-chained audit**: Every governance event is append-only with prev_hash linking.

## The Bigger Picture

This isn't just about API keys. This is the onramp to the Agentic Internet.

When an agent joins a mesh, it presents its certificate chain. That chain traces back to a Genesis key. That Genesis key traces back to a human — through their face, their fingerprint, or their hardware wallet. Not through a password. Not through an OAuth token from a corporate SSO. Through *them*.

That's what ZeroPoint is building: the infrastructure where identity is sovereign, governance is cryptographic, and the default path — the path of least resistance — is also the path of maximum accountability.

The onboarding UX is the first 60 seconds of that reality.
