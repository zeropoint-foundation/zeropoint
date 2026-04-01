# Browser-Based Onboarding UX — Complete Journey Map

> Served from `zp serve` at `localhost:3000/onboard`
> Reuses ZP design system: `--bg: #0a0a0c`, `--accent: #7eb8da`, Inter + JetBrains Mono
> Voice narrations throughout, using the existing narrate-btn + auto-advance pattern

## Design Principles

1. **Information sovereignty is the foundation.** In order to live free we must take agency and responsibility for our own information — else we will be owned. Every step in this onboarding exists to transfer control from institutional intermediaries back to the individual. This is not an abstract ideal; it's the operating principle.
2. **Teach the paradigm shift.** Every step contrasts the old model (delegated trust to authorities, credentials stored by platforms, identity issued by institutions) with the new model (self-sovereign cryptographic proof, local-first encryption, identity you create and own). Users must understand *why* this is different before they can appreciate *what* they're building.
3. **One ceremony, one sitting.** A new user goes from zero to governed in under 5 minutes.
4. **Show, then explain.** Every step shows what just happened, then offers a narrated "why."
5. **Smart defaults, escape hatches.** The recommended path is one click per step. Power users can expand.
6. **Honest about security.** Name the exact protection mechanism. No aspirational claims.
7. **The CLI runs underneath.** The browser UI orchestrates `zp` commands via WebSocket. The terminal output streams live into a terminal pane. Users see both the polished UI and the real commands — nothing is hidden.
8. **Your body is the root credential.** Biometric verification is the sovereignty-first security boundary. Not a convenience feature bolted on later — it's the natural terminus of the trust chain. Your Genesis secret is gated by your physical presence. An agent can't act without you there.

---

## Architecture

```
Browser (localhost:3000/onboard)
    │
    ├── WebSocket ──→ zp serve (Axum)
    │                   │
    │                   ├── Executes: zp init (Genesis ceremony)
    │                   ├── Executes: zp configure scan (tool discovery)
    │                   ├── Executes: zp configure vault-add (credential store)
    │                   ├── Executes: zp configure auto (auto-configure)
    │                   └── Returns: JSON events (progress, results, errors)
    │
    └── Static assets (HTML, CSS, JS, narration MP3s)
         served from /onboard/ route
```

The server exposes a `/api/onboard/ws` WebSocket endpoint. The browser sends commands (`{ "action": "genesis", "operator_name": "Ken" }`), the server executes them, and streams structured JSON events back (`{ "event": "step_complete", "step": "genesis", "data": { ... } }`). This keeps the browser stateless — if you refresh, the server reports current state.

---

## Narrative Arc — The Three Acts

The onboarding is a story. Each step teaches a piece of a paradigm shift that most users have never encountered. The narrative unfolds in three acts:

### Act 1: Sovereignty (Steps 0–4) — "I own my trust"

The old model: Your identity is issued by an authority. Your credentials are stored by platforms. Your inference runs on someone else's hardware. Your security depends on someone else's infrastructure. You trust because you have no choice.

The new model: You create your own cryptographic root of trust. Your credentials are encrypted in a vault only you can unlock. You choose where inference happens — locally, in the cloud, or both. Your security boundary is your physical body — not a password in someone else's database.

**Teaching moment:** Information sovereignty is not a feature. It's the precondition for freedom in a world where autonomous agents act on your behalf. If you don't own your keys, whoever does own them owns *you* — your agents, your data, your decisions. And if your inference runs exclusively on someone else's hardware, every prompt, every response, every chain-of-thought is visible to them. Sovereignty means choosing where computation happens, not just where keys are stored.

### Act 2: Governance (Steps 5–7) — "I enforce my rules"

The old model: You give API keys to tools and hope they behave. The platform decides what's allowed. You find out about misuse after it happens — if you find out at all.

The new model: Every API call routes through your policy engine. You define the rules. Every request is metered, every response receipted, every action auditable. The governance proxy is your checkpoint — nothing passes without your consent.

**Teaching moment:** Governance isn't restriction — it's awareness. You can't make informed decisions about what your agents do if you can't see what they're doing. The proxy makes the invisible visible.

### Act 3: Attestation (Step 8 + Post-onboard) — "I prove it to the world"

The old model: Trust requires institutions. Notaries, certificate authorities, regulatory bodies. Trust doesn't travel — it's trapped inside organizational boundaries.

The new model: You anchor your Genesis identity to a public ledger. Your governance proofs become verifiable by anyone, anywhere. Trust becomes portable — it crosses organizational boundaries because it's rooted in cryptographic proof, not institutional authority. Concretely: your agents can prove who they work for, your governance chain becomes an unfakeable reputation, and multi-agent workflows get peer-to-peer trust verification without any central authority.

**Teaching moment:** Local-only genesis is the default and the right starting point. Public attestation is a conscious, irreversible act — putting your cryptographic root on a permanent public record. The onboarding seeds this idea in Step 2 ("That's Act 3. We'll get there.") and pays it off in Step 8 by leading with what attestation *unlocks*, not just what it *costs*.

---

## The Journey: 8 Steps

### Step 0: Welcome
**What the user sees:** A clean splash with the ZP wordmark, a paradigm-setting statement, and one button.

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│                      zeropoint                          │
│                                                         │
│         Portable trust for the Agentic Age.             │
│                                                         │
│  ┌─ the old model ─────────────────────────────────┐    │
│  │ Your identity is issued by authorities. Your     │    │
│  │ credentials are stored by platforms. Your trust   │    │
│  │ depends on institutions you don't control.        │    │
│  │ In the Agentic Age, that model breaks — because   │    │
│  │ the agents acting on your behalf inherit whatever  │    │
│  │ trust model you're using. If you don't own your   │    │
│  │ keys, whoever does owns your agents.              │    │
│  └───────────────────────────────────────────────────┘   │
│                                                         │
│  ┌─ the new model ─────────────────────────────────┐    │
│  │ You create your own cryptographic root of trust. │    │
│  │ Your credentials live in a vault only you can     │    │
│  │ unlock. Your governance rules are yours to write.  │    │
│  │ Everything — vault, policies, agent certificates — │    │
│  │ derives from one key, created right now, by you.  │    │
│  └───────────────────────────────────────────────────┘   │
│                                                         │
│              [ Begin Genesis ]                          │
│                                                         │
│    🔊 Narrate                                           │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**Narration cue** (`onboard-welcome.mp3`):
> "Welcome to ZeroPoint. Before we begin, let's be clear about what's happening here — and why it matters. Right now, your digital identity is issued by institutions. Your credentials are stored by platforms. Your trust depends on infrastructure you don't control. That worked when humans were the only actors. But we're entering the Agentic Age — where autonomous agents act on your behalf, making decisions, calling APIs, moving data. Those agents inherit whatever trust model you're using. If your keys live on someone else's server, your agents answer to someone else's rules. In order to live free, you must take agency and responsibility for your own information — otherwise, you will be owned. That's what the next few minutes are about. We're going to create your cryptographic root of trust — a single key that everything derives from. Your vault, your governance policies, your agent certificates — all yours. Let's begin."

**What happens underneath:** Nothing yet. This is orientation — but it's the most important step in the entire flow. The user must understand the *why* before they touch the *what*.

---

### Step 1: How Will You Prove It's You?
**What the user sees:** A key source picker — three cards, one recommended based on platform detection.

```
┌─────────────────────────────────────────────────────────┐
│  01 ─ Sovereignty Boundary                              │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  Your Genesis secret needs a guardian — something       │
│  that proves YOU authorized an action, not just a       │
│  process running on your machine. How should            │
│  ZeroPoint verify your presence?                        │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │                                                 │    │
│  │  ┌── biometric ─── recommended ──────────────┐  │    │
│  │  │                                           │  │    │
│  │  │  Touch ID / Face ID / Fingerprint         │  │    │
│  │  │                                           │  │    │
│  │  │  Your body is the credential. The Genesis │  │    │
│  │  │  secret is locked behind your biometric — │  │    │
│  │  │  no password to phish, no file to copy.   │  │    │
│  │  │  Agents can't act without you physically  │  │    │
│  │  │  present.                                 │  │    │
│  │  │                                           │  │    │
│  │  │  macOS: Touch ID (Secure Enclave)         │  │    │
│  │  │  Linux: fprintd (fingerprint reader)      │  │    │
│  │  │                                           │  │    │
│  │  └───────────────────────────────────────────┘  │    │
│  │                                                 │    │
│  │  ┌── login password ─────────────────────────┐  │    │
│  │  │                                           │  │    │
│  │  │  OS Credential Store                      │  │    │
│  │  │                                           │  │    │
│  │  │  Your login password gates the Genesis    │  │    │
│  │  │  secret. macOS Keychain or Linux Secret   │  │    │
│  │  │  Service. Solid default. Can upgrade to   │  │    │
│  │  │  biometric later without re-keying.       │  │    │
│  │  │                                           │  │    │
│  │  └───────────────────────────────────────────┘  │    │
│  │                                                 │    │
│  │  ┌── file-based ─────────────────────────────┐  │    │
│  │  │                                           │  │    │
│  │  │  Encrypted File on Disk                   │  │    │
│  │  │                                           │  │    │
│  │  │  For headless servers, CI, or systems     │  │    │
│  │  │  without a credential store. The secret   │  │    │
│  │  │  is AES-encrypted on disk. Functional     │  │    │
│  │  │  but weaker — anyone with disk access     │  │    │
│  │  │  and your password can derive the key.    │  │    │
│  │  │                                           │  │    │
│  │  └───────────────────────────────────────────┘  │    │
│  │                                                 │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  ┌─ why this matters ────────────────────────────────┐  │
│  │ If an agent runs on your machine, it can access   │  │
│  │ files and env vars. It can't fake your fingerprint│  │
│  │ or your face. Biometric verification means the    │  │
│  │ Genesis secret — and everything derived from it — │  │
│  │ requires YOUR physical presence to unlock.        │  │
│  │                                                   │  │
│  │ This becomes especially important when agents     │  │
│  │ interact via live camera. Your biometric IS the   │  │
│  │ continuous proof that a human is in the loop.     │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  ┌─ what if my biometric changes? ───────────────────┐  │
│  │                                                   │  │
│  │ Your OS biometric adapts over time — Face ID      │  │
│  │ updates as you age, grow a beard, wear glasses.   │  │
│  │ Touch ID stores up to 5 fingerprints. Gradual     │  │
│  │ change is handled.                                │  │
│  │                                                   │  │
│  │ For catastrophic change (injury, surgery), your   │  │
│  │ biometric is never the ONLY path. ZeroPoint       │  │
│  │ creates a recovery kit at genesis — a one-time    │  │
│  │ recovery code, printed or stored offline, that    │  │
│  │ lets you re-enroll a new biometric or fall back   │  │
│  │ to password. Your Genesis secret stays intact.    │  │
│  │ Only the gate in front of it changes.             │  │
│  │                                                   │  │
│  │ You can also register multiple biometrics (face   │  │
│  │ + fingerprint), or designate a trusted second     │  │
│  │ operator who can authorize recovery.              │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│              [ Continue → ]                             │
└─────────────────────────────────────────────────────────┘
```

**Narration cue** (`onboard-sovereignty.mp3`):
> "Here's the first real departure from the old model. Traditionally, proving your identity means presenting credentials issued by someone else — a password stored in a corporate database, a token granted by an OAuth provider, a certificate signed by a certificate authority. Someone else holds the keys to your identity. They can revoke it, surveil it, or lose it in a breach. ZeroPoint inverts this. Your Genesis secret — the root of your entire trust chain — needs a guardian that answers only to you. A password can be phished, guessed, or stolen from a database. A file on disk can be copied by any process running as your user. But your fingerprint? Your face? Those are yours. They can't be exfiltrated. An agent running on your machine — no matter how capable — cannot fake your biometric. This is what sovereignty-first security looks like in practice: your physical presence is the boundary between authorized and unauthorized. No institution mediates. No platform can revoke. If you have Touch ID, Face ID, or a fingerprint reader, ZeroPoint locks your Genesis secret behind it. Every vault access, every high-privilege action — your body is the proof. And if your biometric changes? ZeroPoint creates a recovery kit during genesis — a 24-word mnemonic you print or store offline. It lets you re-enroll a new biometric without losing your identity. The Genesis secret stays intact. Only the gate in front of it changes. Choose biometric if your hardware supports it. Login password is the solid default. File-based is for servers and CI."

**Platform detection:**
The server detects available biometric hardware on init:
- macOS: Check for Touch ID via `LAContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` — the Keychain's `kSecAccessControlBiometryCurrentSet` flag
- Linux: Check for fprintd service (`systemctl is-active fprintd`)
- No hardware detected: Biometric card is grayed out, login password becomes recommended

**What happens underneath:** Server returns `{ "biometric_available": true, "biometric_type": "touchid", "credential_store_available": true, "platform": "macos" }`. The UI highlights the best available option. User selection is stored as `sovereignty_mode` in `zeropoint.toml`.

**Key technical detail — macOS biometric gating:**
The `keyring` crate supports `SecAccessControl` with biometric access policy. When the user selects biometric, `save_genesis_to_credential_store()` uses `kSecAccessControlBiometryCurrentSet` instead of the default access control. This means every read of the Genesis secret from Keychain triggers a Touch ID prompt. The Secure Enclave holds the biometric template — it never leaves the hardware.

**Key technical detail — continuous presence (v0.2+):**
When agents interact via live camera, ZeroPoint can require periodic re-verification — a Touch ID tap every N minutes, or continuous face presence via the camera feed. This isn't surveillance; the camera feed is processed locally, never transmitted. It's a local presence assertion: "a human is still here." This maps naturally to the governance model — high-privilege actions (vault access, credential injection, policy changes) require fresh biometric proof.

---

### Step 2: Identity — The Genesis Ceremony
**What the user sees:** An input for their operator name, a "Create Genesis Key" button, and a live terminal pane showing the ceremony as it runs.

```
┌─────────────────────────────────────────────────────────┐
│  02 ─ Identity                                          │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  Your operator name identifies you in certificate       │
│  chains and audit logs. It's not a username — it's      │
│  the subject line on your root certificate.             │
│                                                         │
│  Operator name: [ Ken_________________________ ]        │
│                                                         │
│              [ Create Genesis Key ]                     │
│                                                         │
│  ┌─ terminal ─────────────────────────────────────────┐ │
│  │  ZeroPoint Genesis                                 │ │
│  │  ─────────────────                                 │ │
│  │  Generating operator keypair...        ✓ Ed25519   │ │
│  │  Sealing constitutional bedrock...     ✓ 5 gates   │ │
│  │  Sealing secret in OS credential store...          │ │
│  │  ✓ genesis record + secret sealed in Keychain      │ │
│  │                                                    │ │
│  │  Operator identity: 7eb8da3f...                    │ │
│  │  Constitutional hash: a9c4f2...                    │ │
│  └────────────────────────────────────────────────────┘ │
│                                                         │
│  ┌─ what just happened ──────────────────────────────┐  │
│  │ ✓ Ed25519 keypair generated (Genesis + Operator)  │  │
│  │ ✓ Constitutional bedrock sealed (5 governance     │  │
│  │   gates: 2 constitutional, 3 operational)         │  │
│  │ ✓ Genesis secret stored in macOS Keychain         │  │
│  │   (protected by your login password)              │  │
│  │ ✓ Genesis record written to ~/.zeropoint/         │  │
│  │ ✓ zeropoint.toml created with defaults            │  │
│  │                                                   │  │
│  │ Your secret key is NOT on disk. It lives in your  │  │
│  │ OS credential store, gated by your chosen         │  │
│  │ sovereignty boundary (biometric / login password). │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│              [ Continue → ]                             │
└─────────────────────────────────────────────────────────┘
```

**Narration cue** (`onboard-genesis.mp3`):
> "What just happened is something that's never happened to most people before: you created your own root of trust. In the old model, your digital identity is issued to you — by a company, a government, a platform. They hold the master copy. They can revoke it. You are a tenant in their system. What ZeroPoint just created is different. This is an Ed25519 keypair — the same cryptography that secures SSH, TLS, and digital signatures worldwide — but it wasn't issued by anyone. You generated it. You hold the only copy of the secret half. It's sealed in your operating system's credential store, gated by the sovereignty boundary you chose. Your Operator key was derived from this Genesis key. Both are in a certificate chain — like TLS but for *your* identity, signed by *you*. Nobody else has a copy. Nobody can revoke it. Nobody even needs to know it exists — until you choose to prove something with it. That's the shift: from identity-as-a-service to identity-as-a-property-right. For now, this key is local. Only you know it exists. But later, if you choose, you can anchor it to a public ledger — and everything changes. Your agents can prove who they work for. Other agents can verify your governance before trusting you. That's Act 3. We'll get there."

**Conditional messaging (critical):**
The "what just happened" box adapts based on what actually happened:

| Scenario | Message |
|----------|---------|
| Biometric (macOS Touch ID) | "Genesis secret sealed in macOS Keychain, gated by Touch ID (Secure Enclave)" |
| Biometric (macOS Face ID) | "Genesis secret sealed in macOS Keychain, gated by Face ID (Secure Enclave)" |
| Biometric (Linux fprintd) | "Genesis secret sealed in Secret Service, gated by fingerprint (fprintd)" |
| Login password (macOS) | "Genesis secret sealed in macOS Keychain (protected by login password)" |
| Login password (Linux) | "Genesis secret sealed in Secret Service (GNOME Keyring / KWallet)" |
| Fell back to file | "Genesis secret written to ~/.zeropoint/keys/genesis.secret (OS credential store unavailable — will auto-migrate when available)" |
| Credential store + file fallback detail | "Note: Your credential store wasn't available, so the secret is on disk. When your credential store becomes available, ZeroPoint will automatically migrate the secret and securely delete the file." |

**What happens underneath:** Server executes `zp init` with the provided operator name. WebSocket streams the terminal output line by line. Server also returns structured JSON with `genesis_public_key`, `constitutional_hash`, `secret_in_credential_store` boolean, and platform info.

---

### Step 3: Understanding Your Vault
**What the user sees:** A brief explainer (no action required) about how credentials will be stored.

```
┌─────────────────────────────────────────────────────────┐
│  03 ─ Your Vault                                        │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  ZeroPoint derives a vault key from your Genesis        │
│  secret. This vault encrypts every credential you       │
│  store — API keys, tokens, connection strings — with    │
│  ChaCha20-Poly1305 authenticated encryption.            │
│                                                         │
│  ┌─ how it works ────────────────────────────────────┐  │
│  │                                                   │  │
│  │  Genesis Secret (in credential store)             │  │
│  │       │                                           │  │
│  │       ▼                                           │  │
│  │  BLAKE3-keyed("zp-credential-vault-v1")           │  │
│  │       │                                           │  │
│  │       ▼                                           │  │
│  │  Vault Key (ephemeral — exists only in memory)    │  │
│  │       │                                           │  │
│  │       ▼                                           │  │
│  │  ChaCha20-Poly1305 → Your encrypted credentials   │  │
│  │                                                   │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  You don't manage the vault key. It's derived on        │
│  demand from your Genesis secret, used, then wiped      │
│  from memory. There is nothing to remember, back up,    │
│  or rotate. Your Genesis key IS your credential.        │
│                                                         │
│  ┌─ what you can change later ───────────────────────┐  │
│  │ • `zp vault export --encrypted` — portable backup │  │
│  │ • `zp vault import` on new machine + re-derive    │  │
│  │ • Hardware wallet users: plug in, derive, done    │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│              [ Continue → ]                             │
└─────────────────────────────────────────────────────────┘
```

**Narration cue** (`onboard-vault.mp3`):
> "Think about where your API keys live right now. In a .env file. In a password manager run by a company. In a cloud provider's secrets manager. In every case, someone else's infrastructure sits between you and your credentials. If that infrastructure is breached, your keys are exposed. If that company changes terms, your access can be cut. ZeroPoint's vault is different. Every API key you're about to add gets encrypted with a vault key derived from your Genesis secret — the key you just created and that only you control. The derivation uses BLAKE3, keyed with a domain separator so the vault key can never collide with anything else. The vault key only exists in memory while it's being used, then it's zeroized — overwritten with zeros. No cloud. No third party. No infrastructure that isn't yours. Your Genesis key is your credential. If you move to a new machine, you export an encrypted vault backup and re-derive on the other side. Your credentials travel with you because they belong to you."

**What happens underneath:** Nothing — this is an informational step. The server confirms vault key derivation works by returning a success signal. If derivation fails (credential store locked, etc.), this step shows the error and offers recovery guidance.

---

### Step 4: Inference Posture
**What the user sees:** A clear three-option choice about where AI inference runs, with automatic detection of local inference capability.

```
┌─────────────────────────────────────────────────────────┐
│  04 ─ Inference Source                                   │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  Where does your AI inference run? This determines      │
│  what credentials you'll need and how ZeroPoint         │
│  governs your agent traffic.                            │
│                                                         │
│  ┌─ the old model ─────────────────────────────────┐    │
│  │ Your prompts, your data, your chain-of-thought  │    │
│  │ — all sent to someone else's hardware. Every    │    │
│  │ inference call is visible to the provider. You  │    │
│  │ pay per token. They decide the terms.           │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  ┌─ the new model ─────────────────────────────────┐    │
│  │ You choose where computation happens. Local     │    │
│  │ models keep everything on your hardware. Cloud   │    │
│  │ models give you access to frontier capability.   │    │
│  │ Mixed gives you both — and your governance      │    │
│  │ proxy routes each call to the right place.      │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │                                                  │   │
│  │  ┌── local only ────────────────────────────┐    │   │
│  │  │                                          │    │   │
│  │  │  ✓ Ollama detected (v0.4.7)              │    │   │
│  │  │    Models: llama3.1:8b, codellama:13b    │    │   │
│  │  │                                          │    │   │
│  │  │  All inference stays on your hardware.   │    │   │
│  │  │  No API keys needed. No data leaves      │    │   │
│  │  │  your machine. Maximum privacy.          │    │   │
│  │  │                                          │    │   │
│  │  └──────────────────────────────────────────┘    │   │
│  │                                                  │   │
│  │  ┌── cloud only ────────────────────────────┐    │   │
│  │  │                                          │    │   │
│  │  │  Use OpenAI, Anthropic, Google, etc.     │    │   │
│  │  │  Frontier models. API keys required.     │    │   │
│  │  │  All calls governed through the proxy.   │    │   │
│  │  │                                          │    │   │
│  │  └──────────────────────────────────────────┘    │   │
│  │                                                  │   │
│  │  ┌── mixed ─── recommended ─────────────────┐    │   │
│  │  │                                          │    │   │
│  │  │  Local models for routine tasks.         │    │   │
│  │  │  Cloud models for frontier capability.   │    │   │
│  │  │  The governance proxy routes each call   │    │   │
│  │  │  to the right backend — you set the      │    │   │
│  │  │  rules for what stays local.             │    │   │
│  │  │                                          │    │   │
│  │  └──────────────────────────────────────────┘    │   │
│  │                                                  │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│  ┌─ local inference status ────────────────────────┐    │
│  │ ✓ Ollama detected (v0.4.7) at localhost:11434   │    │
│  │   2 models: llama3.1:8b, codellama:13b          │    │
│  │ ✓ LM Studio detected at localhost:1234          │    │
│  │   1 model: mistral-7b                           │    │
│  │                                                  │    │
│  │   OR:                                            │    │
│  │                                                  │    │
│  │ ⚠ No local inference runtime detected.           │    │
│  │   Popular options: Ollama · LM Studio · Jan      │    │
│  │   You can add local inference anytime.            │    │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│              [ Continue → ]                             │
└─────────────────────────────────────────────────────────┘
```

**Narration cue** (`onboard-inference.mp3`, ~45s):
> "Here's a sovereignty question most onboarding flows never ask: where does your inference run? Every time you prompt a cloud model — OpenAI, Anthropic, Google — your data, your reasoning, your chain-of-thought is sent to someone else's hardware. They see everything. They meter it. They set the terms. That's fine when you need frontier capability. But for routine tasks — summarization, code completion, local analysis — do you really need to send that data across the wire? Local inference changes the equation. ZeroPoint just scanned your system — your hardware, your memory, your GPU — and checked whether a local runtime is already running. If you have one, great. If not, we'll walk you through the setup right here. Choose a runtime — Ollama, LM Studio, Jan, whatever fits your workflow — and ZeroPoint gives you the exact install commands for your platform, recommends a model that fits your hardware, and tells you why. Every recommendation links to its source. You can verify it yourself. That's how this should work. Mixed mode is the sweet spot for most people: local models handle the routine work, cloud models handle what requires frontier capability, and your governance proxy decides which is which based on rules you define. If you'd rather skip this for now, that's fine too — choose cloud or mixed below and add local inference anytime with `zp configure inference`."

**What happens underneath:** The server does three things on step entry:

1. **System resource detection** — reads RAM, CPU core count, chip model, and GPU/accelerator info (discrete VRAM or unified memory). Platform-specific: `sysctl` on macOS, `/proc/meminfo` + `/proc/cpuinfo` on Linux, `wmic` on Windows. GPU detection via `nvidia-smi`, `rocm-smi`, `system_profiler`, or `wmic`. Returns `{ "ram_gb": 32, "cpu_cores": 10, "chip": "Apple M2 Pro", "gpu": "Apple M2 Pro (unified 32GB)", "inference_memory_gb": 32, "unified_memory": true, "local_inference_fit": "strong", "recommendation": "..." }`

2. **Local runtime detection** — probes common local inference endpoints in parallel:
   - **Ollama** (`localhost:11434`) — proprietary `/api/tags` + `/api/version`
   - **LM Studio** (`localhost:1234`) — OpenAI-compatible `/v1/models`
   - **llama.cpp / LocalAI** (`localhost:8080`) — OpenAI-compatible `/v1/models`
   - **Jan** (`localhost:1337`) — OpenAI-compatible `/v1/models`
   - **vLLM** (`localhost:8000`) — OpenAI-compatible `/v1/models`
   Returns `{ "available": true, "runtimes": [{ "name": "Ollama", "endpoint": "...", "version": "0.4.7", "models": [...] }], "models": [...], "system": { ... } }`

3. User's choice is stored as `inference_posture` in `zeropoint.toml` — one of `"local"`, `"cloud"`, or `"mixed"`

**Hardware-aware recommendation:**

The "recommended" tag is not static — it adapts to the user's actual hardware. This is stewardship, not presumption: the user still sees all three options and can choose any of them. The recommendation just helps them understand what their system can handle.

| System profile | Local runtime status | Recommendation |
|---------------|---------------------|----------------|
| 16+ GB inference memory ("strong") | Runtime(s) detected | **Mixed** — hardware note + "local models will run well here." |
| 16+ GB inference memory ("strong") | Not detected | **Mixed** — "your hardware can handle local models. Install a local runtime when ready." |
| 8–15 GB inference memory ("moderate") | Runtime(s) detected | **Mixed** — "smaller local models (7B–8B) will work." |
| 8–15 GB inference memory ("moderate") | Not detected | **Cloud** — "cloud gives you access to larger models. Add local inference later." |
| <8 GB / no GPU ("limited") | Any | **Cloud** — "cloud inference is the practical choice for now." |
| Detection failed ("unknown") | Any | **Mixed** — safe default with explanation |

The recommendation appears as a one-line note in the system status box and as a "recommended for your system" tag on the appropriate posture card. It never hides or disables options — it informs the choice.

**Runtime-adaptive behavior:**
| Detection result | UI behavior |
|-----------------|-------------|
| One or more runtimes detected with models | Status: green check per runtime with name, endpoint, version, and model list. Local card shows all available models. |
| Runtime detected but no models loaded | Status: yellow warning. Setup assistant shows Phase 3 (model recommendation with hardware-specific suggestion and pull command). |
| No runtime detected, capable hardware | Status: warning. Setup assistant activates with three phases: (1) choose a runtime, (2) platform-specific install guide with copy-pasteable commands, (3) model recommendation after re-detect. |
| No runtime detected, limited hardware | Same as above, but with a note that small models will work and Mixed/Cloud may be a better fit. |

**Stewarded setup flow:**

When no local runtime is detected, ZeroPoint doesn't just link to download pages — it walks the user through the entire setup. This is the same philosophy as the Genesis key flow: stewardship, not abandonment.

The setup assistant has four phases:

1. **Choose a runtime** — Three buttons: Ollama (CLI · lightweight), LM Studio (visual · beginner-friendly), Jan (desktop · one-click). Each button triggers a `get_setup_guidance` request that returns platform-specific instructions.

2. **Install instructions** — Platform-specific commands:
   - macOS: `brew install ollama` or direct download
   - Linux: `curl -fsSL https://ollama.com/install.sh | sh`
   - Windows: `winget install Ollama.Ollama` or direct installer
   - GUI runtimes: download link + in-app setup notes

   A "I've installed it — check again" button re-probes all endpoints.

3. **Model recommendation** — Based on the user's hardware profile (as of March 2026):
   - 32+ GB: **Qwen 3 8B** (~5.2 GB) — leads benchmarks on math, coding, reasoning; thinking mode for complex tasks. Alt: Gemma 3 12B (multimodal, 128K context).
   - 16–31 GB: **Qwen 3 8B** (~5.2 GB) — same model, runs comfortably with headroom. Alt: Llama 3.3 8B (solid all-rounder, largest ecosystem).
   - 8–15 GB: **Gemma 3 4B** (~3.0 GB) — outperforms prior-gen 27B models; multimodal, 60-80 tok/s, fits at Q8 in 8GB. Alt: Phi-4 Mini 3.8B (excels at math/coding, 80.4% on MATH benchmark).
   - <8 GB: **Qwen 3 0.6B** (~523 MB) — smallest model with thinking mode; better than Llama 3.2 1B at half the size. Alt: Gemma 3 1B (multimodal at 1B, 128K context).

   Shows the pull command, download size, and hardware-specific rationale.

   **Updatable without recompiling:** Recommendations can be overridden via `~/.zeropoint/config/model-recommendations.toml`. This file uses a simple `[[tiers]]` format with `min_memory_gb`, `model_id`, `display_name`, `size`, `rationale`, and an optional `[tiers.alternative]` block. If the file doesn't exist, compiled-in defaults are used.

4. **Background pull and continue** — Model downloads (multi-GB) should not block the onboarding flow. When the user initiates a pull, onboarding continues through Steps 5-8. A status indicator notes "Model downloading — will be available when complete." The governance proxy routes to cloud until the local model is ready. Post-onboard, the model becomes available automatically.

The user can skip the setup assistant at any phase — a persistent footer says "choose Cloud or Mixed below and add local inference anytime with `zp configure inference`."

**Impact on subsequent steps:**
- **Local only:** Tool discovery (Step 5) skips cloud API key detection. Credential collection (Step 6) shows only local endpoint configuration. Configure (Step 7) routes all inference through local endpoint(s).
- **Cloud only:** Behaves like the current flow. Tool discovery scans for cloud API keys.
- **Mixed:** Tool discovery scans for both cloud API keys and local endpoints. Credential collection handles both. Configure step writes routing rules for the governance proxy.

---

### Step 5: Tool Discovery
**What the user sees:** An animated scan with results appearing as they're found.

```
┌─────────────────────────────────────────────────────────┐
│  05 ─ Discover Tools                                    │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  ZeroPoint scans your project directories for AI        │
│  tools that use .env files for configuration. Each      │
│  tool's template tells us exactly which credentials     │
│  it needs.                                              │
│                                                         │
│  Scan directory: [ ~/projects_________________ ] [Scan] │
│                                                         │
│  ┌─ results ─────────────────────────────────────────┐  │
│  │                                                   │  │
│  │  OpenMAIC          ⚠ needs: openai, anthropic     │  │
│  │  PentAGI           ⚠ needs: openai, anthropic,    │  │
│  │                           google                  │  │
│  │  Agent-Zero        ✓ ready (defaults)             │  │
│  │  LocalAI           ✓ ready (no keys needed)       │  │
│  │                                                   │  │
│  │  4 tools found · 3 unique credentials needed      │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  One credential can serve multiple tools. The next      │
│  step collects only the unique keys you need.           │
│                                                         │
│              [ Add Credentials → ]                      │
└─────────────────────────────────────────────────────────┘
```

**Narration cue** (`onboard-discover.mp3`):
> "ZeroPoint just scanned your project directories for AI tools. It looks at .env.example files — the templates that tools ship with — and maps each environment variable to a credential in your vault. The key insight is deduplication: if three tools all need an OpenAI API key, that's one credential stored once, injected three times. The next step collects only the unique keys you actually need."

**What happens underneath:** Server executes the equivalent of `zp configure scan` with the provided path. WebSocket streams discovered tools as they're found. The UI builds the results list incrementally.

---

### Step 6: Credential Collection
**What the user sees:** Two sections — detected providers (env vars found in the user's environment) shown prominently at top, and a collapsible catalog of all 22 supported providers grouped by category below. Each card has a "get key" link, key format hint, source attribution, and a Store button.

The provider catalog is **data-driven** — loaded from `providers-default.toml` (embedded in the binary) and merged with any user overrides in `~/.zeropoint/config/providers.toml`. Adding a new provider means adding a TOML block, not changing Rust code.

```
┌─────────────────────────────────────────────────────────┐
│  06 ─ Add Credentials                                   │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  Each credential is encrypted in your vault the         │
│  moment you press Store. No plaintext on disk, no       │
│  cloud intermediary.                                    │
│                                                         │
│  DETECTED IN YOUR ENVIRONMENT                           │
│                                                         │
│  ┌─ OpenAI ──────────────────────── get key ↗ ───────┐  │
│  │  ✓ Found: OPENAI_API_KEY                          │  │
│  │  Used by: OpenMAIC, PentAGI                       │  │
│  │  starts with sk-proj-                             │  │
│  │  [ OPENAI_API_KEY__________________ ] [Store]     │  │
│  │  docs ↗ · verified 2026-03-22                     │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  ┌─ Anthropic ──────────────────── get key ↗ ────────┐  │
│  │  ✓ Found: ANTHROPIC_API_KEY                       │  │
│  │  Used by: OpenMAIC, PentAGI                       │  │
│  │  starts with sk-ant-                              │  │
│  │  [ ANTHROPIC_API_KEY_______________ ] [Store]     │  │
│  │  docs ↗ · verified 2026-03-22                     │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  ▸ All providers (20)                                   │
│    ┌───────────────────────────────────────────────┐    │
│    │  LLM / FOUNDATION MODELS                      │    │
│    │  ─ Google Gemini ──────────── get key ↗       │    │
│    │  ─ Mistral AI ─────────────── get key ↗       │    │
│    │  ─ Cohere ──────────────────── get key ↗      │    │
│    │  ... (Groq, DeepSeek, xAI, Perplexity, etc.)  │    │
│    │                                                │    │
│    │  EMBEDDING                                     │    │
│    │  ─ Voyage AI ───────────────── get key ↗      │    │
│    │  ─ Nomic ───────────────────── get key ↗      │    │
│    │                                                │    │
│    │  CLOUD PLATFORMS                               │    │
│    │  ─ AWS Bedrock ─────────────── get key ↗      │    │
│    │  ─ Azure OpenAI ────────────── get key ↗      │    │
│    │  ─ Google Vertex AI ────────── get key ↗      │    │
│    │                                                │    │
│    │  AGGREGATORS                                   │    │
│    │  ─ OpenRouter ──────────────── get key ↗      │    │
│    └───────────────────────────────────────────────┘    │
│                                                         │
│  2 of 22 credential(s) stored                           │
│                                                         │
│              [ Continue → ]  [ Skip remaining ]         │
└─────────────────────────────────────────────────────────┘
```

#### Provider Catalog Architecture

Three layers:

| Layer | File | Purpose |
|-------|------|---------|
| **Embedded defaults** | `crates/zp-server/assets/providers-default.toml` | Compiled into binary via `include_str!`. Curated by ZeroPoint. |
| **User overrides** | `~/.zeropoint/config/providers.toml` | Same format. Entries with matching `id` replace defaults. New entries appended. |
| **Detection engine** | `load_provider_catalog()` + `scan_providers()` in `onboard.rs` | Generic. Reads merged catalog, scans env vars, returns detection status. |

Each provider entry:

```toml
[[providers]]
id = "openai"
name = "OpenAI"
category = "llm"                          # llm | embedding | platform | aggregator | search
env_patterns = ["OPENAI_API_KEY"]         # env vars to scan for
key_hint = "starts with sk-proj-"         # format hint shown in UI
base_url = "https://api.openai.com/v1"    # API endpoint (for proxy routing)
key_url = "https://platform.openai.com/api-keys"  # "get key" link
docs_url = "https://platform.openai.com/docs"     # documentation
supports_org = true                       # org-level key support
source_url = "https://platform.openai.com/docs"   # honest sourcing
last_verified = "2026-03-22"              # when this entry was verified
```

`detect_provider()` is now catalog-driven — it loads the catalog and checks exact env var matches against `env_patterns`. No hardcoded provider list in Rust.

**Narration cue** (`onboard-credentials.mp3`):
> "Now we add your API keys — but notice how this is different from what you're used to. Normally, you'd paste an API key into a .env file, or hand it to a secrets manager run by a cloud provider. The key sits in plaintext on disk, or in someone else's infrastructure. If the machine is compromised, or the provider is breached, your keys are exposed. Here, the moment you press Store, the key is encrypted in your vault — ChaCha20-Poly1305, authenticated encryption — using a key derived from the Genesis secret that only you control. The plaintext never touches disk. It goes straight from this page to your local vault over a local WebSocket connection. No cloud. No intermediary. If you don't have a key yet, skip it. You can always add it later with `zp configure vault-add`."

**Input behavior:**
- Input type is `password` (masked by default)
- Toggle eye icon to reveal
- "Store" button sends the value over WebSocket, server stores in vault
- On success: input becomes read-only, shows masked value (first 6 + last 2 chars)
- On skip: card grays out, shows "(skipped — add later)"

**What happens underneath:** On step entry, the client sends `get_provider_catalog`. The server loads the merged catalog, scans env vars, and returns a `provider_catalog` event with all providers sorted (detected first) and detection status. For each credential stored, the server executes `vault.store("{id}/api_key", value)` and returns `credential_stored`.

---

### Step 7: Configure & Govern
**What the user sees:** A list of ready tools with a single "Configure All" button, plus an optional governance proxy toggle.

```
┌─────────────────────────────────────────────────────────┐
│  07 ─ Configure                                         │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  ZeroPoint will now write .env files for each tool,     │
│  injecting your vault credentials. If the governance    │
│  proxy is enabled, API URLs are rewritten to route      │
│  through ZeroPoint for policy checks, cost metering,    │
│  and signed receipts.                                   │
│                                                         │
│  Ready to configure:                                    │
│    ✓ OpenMAIC                                           │
│    ✓ PentAGI                                            │
│    ✓ Agent-Zero                                         │
│    ✓ LocalAI                                            │
│                                                         │
│  ┌─ Governance Proxy ────────────────────────────────┐  │
│  │                                                   │  │
│  │  The governance proxy is a local HTTP server that │  │
│  │  sits between your tools and their API providers. │  │
│  │  Every call passes through your policy gates      │  │
│  │  before forwarding. You get:                      │  │
│  │                                                   │  │
│  │  • Policy enforcement (block/warn/allow per gate) │  │
│  │  • Cost metering (token counts, spend tracking)   │  │
│  │  • Signed receipts (hash-chained audit trail)     │  │
│  │                                                   │  │
│  │  [ ✓ ] Enable governance proxy (port 3000)        │  │
│  │                                                   │  │
│  │  You can enable this later: `zp proxy start`      │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│              [ Configure All ]                          │
│                                                         │
│  ┌─ terminal ─────────────────────────────────────────┐ │
│  │  Configuring OpenMAIC... ✓                         │ │
│  │  Configuring PentAGI... ✓                          │ │
│  │  Configuring Agent-Zero... ✓                       │ │
│  │  Configuring LocalAI... ✓                          │ │
│  │                                                    │ │
│  │  4/4 tools configured.                             │ │
│  │  API calls route through localhost:3000/api/v1/    │ │
│  └────────────────────────────────────────────────────┘ │
│                                                         │
│              [ Continue → ]                             │
└─────────────────────────────────────────────────────────┘
```

**Narration cue** (`onboard-configure.mp3`):
> "This is where Act 2 begins — governance. In the old model, you give API keys to tools and hope for the best. You have no visibility into what calls are being made, no way to enforce limits, no audit trail. If an agent goes rogue, you find out when the bill arrives — or when the damage is done. ZeroPoint changes this. If you enable the governance proxy, every API call from your tools routes through your local policy engine. Your tools think they're talking directly to OpenAI or Anthropic, but every request is checked against your governance gates, metered for cost, and stamped with a signed receipt that chains cryptographically to the one before it. This isn't surveillance — it's awareness. You can't govern what you can't see. You can turn this on now or add it later with `zp proxy start`. Either way, your credentials are already secured in your vault."

**What happens underneath:** Server runs `zp configure auto` (or with proxy flag). Terminal output streams to the browser. Each tool's configuration result is reported as a structured event.

---

### Step 8: Confirmation — You're Governed
**What the user sees:** A summary of everything that was set up, with verification.

```
┌─────────────────────────────────────────────────────────┐
│  08 ─ You're Governed                                   │
│  ═════════════════════════════════════════════════════  │
│                                                         │
│  ┌─ Your Identity ───────────────────────────────────┐  │
│  │  Operator: Ken                                    │  │
│  │  Genesis:  7eb8da3f...                            │  │
│  │  Sovereignty: Touch ID (Secure Enclave)            │  │
│  │  Algorithm: Ed25519 + BLAKE3                      │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  ┌─ Your Vault ──────────────────────────────────────┐  │
│  │  3 credentials encrypted (ChaCha20-Poly1305)      │  │
│  │  Vault key: derived on demand, never stored       │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  ┌─ Your Tools ──────────────────────────────────────┐  │
│  │  ✓ OpenMAIC     — configured, proxied             │  │
│  │  ✓ PentAGI      — configured, proxied             │  │
│  │  ✓ Agent-Zero   — configured, proxied             │  │
│  │  ✓ LocalAI      — configured (local, no proxy)    │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  ┌─ Governance ──────────────────────────────────────┐  │
│  │  Proxy: localhost:3000/api/v1/proxy/              │  │
│  │  Gates: 5 active (2 constitutional, 3 operational)│  │
│  │  Audit: hash-chained receipts in .zeropoint/data/ │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  ┌─ Act 3: Public Attestation ───────────────────────┐  │
│  │                                                   │  │
│  │  Right now, everything you've built is local.     │  │
│  │  Powerful, but visible only to you. Public        │  │
│  │  attestation changes what's possible:             │  │
│  │                                                   │  │
│  │  → Your agents can prove who they work for.       │  │
│  │    Other agents can verify before trusting.       │  │
│  │  → Your governance chain becomes a verifiable     │  │
│  │    track record — reputation that can't be faked. │  │
│  │  → Multi-agent workflows get mutual trust. Peers  │  │
│  │    verify each other's policies before sharing.   │  │
│  │                                                   │  │
│  │  Anchoring is irreversible — your cryptographic   │  │
│  │  root becomes permanently, publicly verifiable.   │  │
│  │  ZeroPoint doesn't push you there. You go when    │  │
│  │  you're ready.                                    │  │
│  │                                                   │  │
│  │  zp anchor genesis                                │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  ┌─ what you can do next ────────────────────────────┐  │
│  │  zp status        — verify governance state       │  │
│  │  zp secure        — wrap shells and AI tools      │  │
│  │  zp audit log     — view receipt chain            │  │
│  │  zp configure     — add credentials, rescan       │  │
│  │  zp anchor genesis — anchor to public ledger      │  │
│  │  zp doctor        — audit key state (v0.2)        │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  Your tools are governed. Your trust is sovereign. ✦    │
│                                                         │
│  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─   │
│                                                         │
│  Thank you for choosing to live sovereign.               │
│                                                         │
│  You've taken on the responsibility — and the power —   │
│  of owning your own trust. Not everyone will. But you   │
│  did, and that matters.                                  │
│                                                         │
│  Now build a better world — the kind you want to        │
│  live in.                                                │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**Narration cue** (`onboard-complete.mp3`):
> "Let's take stock of what you've built. You created your own cryptographic root of trust — not issued by anyone, not stored on anyone's server. You encrypted your credentials in a vault that only you can unlock. You configured your tools to route through a governance proxy that enforces your rules. Every API call produces a signed receipt. Every receipt chains to the one before it. The chain becomes proof. This is Acts 1 and 2 complete: sovereignty and governance. Now, remember what I said about Act 3? Public attestation. Here's what it unlocks. Your agents can prove who they work for. When your agent contacts another agent, that agent can cryptographically verify your identity and governance posture before trusting anything. Your governance chain becomes a track record — a reputation that can't be faked, because every receipt is hash-chained to the one before it. And in multi-agent workflows, peers can verify each other's policies before sharing data. No central authority deciding who's trustworthy. Just math. Anchoring is irreversible. Once your Genesis is on a public ledger, it's permanent. ZeroPoint doesn't push you there. You go when you're ready. For now: run `zp status` to verify everything, `zp secure` to wrap your shell and AI tools, or `zp audit log` to see your receipt chain. ... And one last thing. Thank you — for choosing to live sovereign. You've taken on the responsibility, and the power, of owning your own trust. Not everyone will. But you did, and that matters. Now build a better world — the kind you want to live in."

---

## Narration Asset Plan

All narration files live in `/assets/narration/onboard/` following the existing convention:

| File | Step | Duration (target) |
|------|------|-------------------|
| `onboard-welcome.mp3` | 0 - Welcome (paradigm intro) | ~40s |
| `onboard-sovereignty.mp3` | 1 - Sovereignty Boundary (old-vs-new: auth) | ~50s |
| `onboard-genesis.mp3` | 2 - Identity (old-vs-new: identity + Act 3 seed) | ~45s |
| `onboard-recovery.mp3` | 2b - Recovery Kit (biometric users only) | ~25s |
| `onboard-vault.mp3` | 3 - Your Vault (old-vs-new: credential storage) | ~35s |
| `onboard-inference.mp3` | 4 - Inference Posture (old-vs-new: where computation runs) | ~40s |
| `onboard-discover.mp3` | 5 - Discover | ~20s |
| `onboard-credentials.mp3` | 6 - Credentials (old-vs-new: secrets management) | ~30s |
| `onboard-configure.mp3` | 7 - Configure (Act 2: governance intro) | ~35s |
| `onboard-complete.mp3` | 8 - Complete (three-act summary + attestation payoff) | ~50s |

**Total narrated walkthrough: ~6 minutes** (biometric path with recovery kit: ~6.5 minutes). The increase from ~3.5 min reflects the paradigm-education, inference posture, and attestation breadcrumbing content. This is deliberate — users need to understand *why* before the *what* has meaning.

The narrate button uses the same play/pause pattern as setup.html. Auto-advance moves to the next step when narration ends. Manual navigation (clicking step tabs) interrupts and plays that step's narration.

---

## Adaptive Content — Platform-Specific Messaging

The server knows the platform at build time. The WebSocket init event includes `{ "platform": "macos" | "linux" | "windows", "biometric_available": bool, "biometric_type": "touchid" | "faceid" | "fprintd" | "windows_hello" | null }`. The UI adapts:

### Genesis Secret Storage
| Platform + Sovereignty Mode | What we say |
|-----------------------------|-------------|
| macOS + biometric (Touch ID) | "Sealed in macOS Keychain, gated by Touch ID (Secure Enclave — biometric never leaves hardware)" |
| macOS + biometric (Face ID) | "Sealed in macOS Keychain, gated by Face ID (Secure Enclave)" |
| macOS + login password | "Sealed in macOS Keychain (protected by your login password — upgrade to biometric anytime)" |
| macOS + credential store failed | "Written to ~/.zeropoint/keys/genesis.secret (Keychain unavailable — will auto-migrate)" |
| Linux + biometric (fprintd) | "Sealed in Secret Service, gated by fingerprint (fprintd)" |
| Linux + login password | "Sealed in Secret Service (GNOME Keyring / KWallet)" |
| Linux + Secret Service unavailable | "Written to ~/.zeropoint/keys/genesis.secret (install gnome-keyring for credential store)" |
| Windows + biometric (Hello) | "Sealed in Windows Credential Manager, gated by Windows Hello" |
| Windows + login password | "Sealed in Windows Credential Manager (protected by your login password — upgrade to Windows Hello biometric anytime)" |
| Windows + Credential Manager failed | "Written to ~/.zeropoint/keys/genesis.secret (Credential Manager unavailable — will auto-migrate)" |
| Any + SECRETS_MASTER_KEY env var | "Derived from SECRETS_MASTER_KEY environment variable (CI/headless mode)" |

### Vault Key Derivation
| Source | What we say |
|--------|-------------|
| CredentialStore | "Vault key derived from credential store (ephemeral, zeroized after use)" |
| LegacyFileMigrated | "Vault key derived from file (will migrate to credential store when available)" |
| EnvironmentVariable | "Vault key derived from SECRETS_MASTER_KEY (CI/headless mode — ensure this is secured)" |

---

## Error States

Every step needs graceful error handling. The UI never dead-ends.

| Error | Step | Recovery |
|-------|------|----------|
| No biometric hardware detected | 1 | Gray out biometric card, recommend login password, explain upgrade path |
| Touch ID enrollment empty | 1 | Explain: enroll a fingerprint in System Settings → Touch ID. Retry button. |
| fprintd not running (Linux) | 1 | Explain: `sudo systemctl enable --now fprintd`. Falls back to login password. |
| Biometric auth failed (wrong finger, timeout) | 1, and any vault access | Retry with biometric, offer temporary fallback to password for this session |
| Biometric permanently changed (post-onboard) | Any vault access | `zp recover --biometric-reset` → enter 24-word mnemonic → re-enroll new biometric |
| Recovery mnemonic lost + biometric changed | Any vault access | Multi-biometric fallback if enrolled; trusted second operator if designated; otherwise credential loss (honest about this) |
| Already initialized | 2 | Show current identity + sovereignty mode, offer to proceed to Step 4 (inference posture) |
| Keychain permission denied (macOS) | 2 | Explain: click "Allow" on the system dialog. Retry button. |
| No Secret Service (Linux) | 2 | Explain: install gnome-keyring. Falls back to file — proceed. |
| No tools found | 4 | Explain: scan looks for .env.example. Offer to add credentials manually or change scan path. |
| Invalid API key format | 5 | Warn but allow store (we don't validate keys against providers). |
| Vault persist failure | 5 | Show error, credentials in memory. Offer retry. |
| Tool configure failure | 6 | Show which tool failed and why. Others continue. |

---

## Relationship to Existing Pages

| Page | Purpose | Audience |
|------|---------|----------|
| `zeropoint.global/setup.html` | Public documentation — explains the `zp secure` flow visually | Pre-install visitors |
| `localhost:3000/onboard` | **Live interactive onboard** — actually runs the ceremony | Post-install users |
| `zp onboard` (CLI) | Same flow, text-only — for headless/SSH/CI | Terminal users |

The public setup.html is a *preview* of what governance looks like. The localhost onboard page *is* the governance ceremony. They share the design system but serve different moments.

---

## Component Reuse from setup.html

| Component | Reuse? | Notes |
|-----------|--------|-------|
| Phase-nav tabs | Yes | 8 steps (0-8), same CSS |
| Terminal simulator | Yes | But now streams real output via WebSocket |
| Narrate button | Yes | Same play/pause/auto-advance pattern |
| Wizard option cards | Yes | Used in Steps 4 (inference posture) and 7 (proxy toggle) |
| Convention boxes | Yes | "What just happened" and "what you can change later" |
| Creates-list | Yes | "What you can do next" in Step 8 |
| Design system vars | Yes | `--bg`, `--accent`, `--text-muted`, fonts, all identical |

New components needed:
- **Credential input card** — provider header, URL, masked input, store button, status
- **Live terminal** — WebSocket-connected, streams real `zp` output (not static mockup)
- **Scan results list** — tool name + status + missing credentials
- **Summary cards** — identity, vault, tools, governance summary in Step 6

---

## WebSocket Protocol

### Client → Server
```json
{ "action": "detect_capabilities" }
{ "action": "init", "operator_name": "Ken", "sovereignty_mode": "biometric" }
{ "action": "scan", "path": "~/projects", "depth": 2 }
{ "action": "vault_add", "vault_ref": "openai/api_key", "value": "sk-..." }
{ "action": "configure", "use_proxy": true, "proxy_port": 3000 }
{ "action": "status" }
```

### Server → Client
```json
{ "event": "platform", "os": "macos", "has_credential_store": true, "biometric_available": true, "biometric_type": "touchid" }
{ "event": "terminal_line", "text": "  Generating operator keypair...        ✓ Ed25519" }
{ "event": "step_complete", "step": "genesis", "data": { "genesis_pub": "7eb8...", "constitutional_hash": "a9c4...", "secret_in_credential_store": true, "sovereignty_mode": "biometric", "sovereignty_detail": "Touch ID (Secure Enclave)", "platform_detail": "macOS Keychain" } }
{ "event": "tool_found", "name": "OpenMAIC", "status": "needs_credentials", "missing": ["openai/api_key", "anthropic/api_key"] }
{ "event": "scan_complete", "total": 5, "ready": 2, "needs_credentials": 3, "unique_credentials": 3 }
{ "event": "credential_stored", "vault_ref": "openai/api_key", "masked": "sk-pro••••ay" }
{ "event": "tool_configured", "name": "OpenMAIC", "success": true }
{ "event": "error", "step": "genesis", "message": "...", "recovery": "..." }
```

---

## Biometric Sovereignty — The Trajectory

Biometric verification isn't a convenience layer on top of passwords. It's the natural terminus of sovereignty-first security, and it becomes the *primary* security surface as agent interaction models evolve.

### Why biometrics are the right default

A password is a shared secret — it exists as information that can be copied, phished, or brute-forced. A file on disk can be read by any process with your user privileges. An environment variable is visible to every child process. None of these are sovereignty boundaries. They're access control mechanisms bolted onto systems designed for human typing.

Your fingerprint is different. Your face is different. They can't be exfiltrated remotely. They can't be replayed from a stolen database (the Secure Enclave stores a mathematical representation, not an image, and it never leaves the hardware). An agent running on your machine — no matter how sophisticated — cannot present your biometric. This makes the biometric the only true sovereignty boundary: it proves a specific human was physically present when an action was authorized.

### Continuous presence verification

Today, biometric auth is a gate — Touch ID once to unlock the Keychain, then the Genesis secret is available for the session. But the trajectory is continuous verification, especially as live camera interaction with agents becomes the norm.

Consider the near-future workflow: you're on camera with an agent, discussing code, reviewing pull requests, approving deployments. The camera is already on. Face presence detection becomes zero-friction continuous authentication. The agent can see you're there. ZeroPoint can verify you're there. High-privilege actions (vault access, credential injection, policy override) are gated by real-time presence — not "were you present 10 minutes ago when you typed a password?"

This maps to three tiers:

| Tier | Gate | When |
|------|------|------|
| **Session** | Biometric once at session start | Default — unlocks vault key for the session |
| **Action** | Biometric per high-privilege action | For sensitive operations (new agent cert, policy change, credential export) |
| **Continuous** | Face presence via camera | For live agent interaction — "human in the loop" becomes cryptographically verifiable |

The continuous tier is where this gets most interesting. If agents interact via live video, the camera feed — processed locally, never transmitted — provides a constant presence signal. ZeroPoint can cryptographically bind that presence to the receipt chain: "this action was performed while human presence was verified at timestamp T." Not a trust-me assertion. A cryptographic receipt backed by hardware biometric.

### Biometric recovery — what happens when your body changes

Biometrics are not immutable. Faces change. Fingers get burned. Surgery happens. A sovereignty model that chains everything to a biometric with no escape hatch is a sovereignty model that can lock you out of your own identity. That's not sovereignty — that's a trap.

The design principle: **the biometric gates the secret, but the secret exists independently of the biometric.** Your Genesis secret is a 32-byte Ed25519 key. It doesn't know or care what biometric is in front of it. The biometric is an access control policy on the Keychain entry (macOS) or Secret Service item (Linux). Change the policy, the secret is unaffected.

**Gradual change** is handled by the OS. Face ID continuously adapts its neural network model — aging, facial hair, glasses, weight changes all get folded in over time. Touch ID stores up to 5 separate fingerprint enrollments. As long as you keep using the device, the biometric model stays current with you.

**Catastrophic change** — severe burns, reconstructive surgery, amputation — requires a recovery path. ZeroPoint provides three, layered by trust model:

**1. Recovery Kit (generated at Genesis, v0.1)**

During the Genesis ceremony, when the user selects biometric sovereignty, ZeroPoint generates a one-time recovery code — a 24-word BIP-39 mnemonic derived from the Genesis secret via a separate BLAKE3 domain ("zp-recovery-v1"). This mnemonic is displayed exactly once with clear instructions to write it down or print it. It is never stored digitally.

The recovery flow:
```
zp recover --biometric-reset
  → Enter recovery mnemonic (24 words)
  → ZeroPoint derives the Genesis secret from the mnemonic
  → Verifies it matches the existing genesis.json public key
  → Prompts: re-enroll biometric or switch to login password
  → Writes the secret to credential store with new access policy
  → Securely deletes any temporary key material
```

The mnemonic IS the Genesis secret in human-readable form. It's not a separate key. This means the recovery code can reconstruct everything — vault key, operator cert, the full derivation chain — without any server, any cloud backup, any third party. Pure local sovereignty.

**2. Multi-biometric enrollment (v0.1)**

Register more than one biometric type. Face ID AND a fingerprint. Left index AND right thumb. If one fails, the other still works. The OS credential store supports this natively — macOS `SecAccessControl` with `BiometryCurrentSet` accepts any enrolled biometric, and you can enroll multiple fingerprints plus Face ID simultaneously.

This is the everyday resilience layer. A bandaged finger doesn't lock you out if your face still works.

**3. Trusted second operator (v0.2)**

For operators who work in teams, ZeroPoint can issue a recovery certificate to a designated second operator. This is a proper cryptographic delegation — the second operator's key can authorize a biometric re-enrollment for the primary, but cannot access the primary's vault contents. It's a recovery-only capability, not a master key.

The ceremony: both operators are present, both authenticate with their own biometrics, a mutual recovery certificate is signed and stored in both chains. Neither can unilaterally access the other's secrets, but either can help the other recover access.

**What the onboarding UI shows:**

After the user selects biometric in Step 1, the Genesis ceremony (Step 2) ends with a recovery kit screen:

```
┌─────────────────────────────────────────────────────────┐
│  Recovery Kit                                           │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  Your Genesis secret can be recovered with these        │
│  24 words. Write them down. Store them offline.         │
│  This screen will not appear again.                     │
│                                                         │
│  ┌───────────────────────────────────────────────────┐  │
│  │                                                   │  │
│  │  1. harvest    7. carbon    13. obtain  19. brave │  │
│  │  2. kingdom    8. winter    14. silent  20. lunar │  │
│  │  3. drift      9. margin    15. anchor  21. frost │  │
│  │  4. copper    10. theory    16. vessel  22. nerve │  │
│  │  5. signal    11. launch    17. prism   23. orbit │  │
│  │  6. beacon    12. summit    18. forge   24. ember │  │
│  │                                                   │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  These words ARE your Genesis secret in human-          │
│  readable form. Anyone who has them can reconstruct     │
│  your entire key hierarchy. Treat them like the         │
│  master key to your house.                              │
│                                                         │
│  [ ] I have written down or printed these words         │
│                                                         │
│  [ Print Recovery Card ]  [ I've stored them → ]        │
│                                                         │
│  ┌─ when would I need this? ─────────────────────────┐  │
│  │ • Your biometric changes (injury, surgery)        │  │
│  │ • You move to a new machine without migration     │  │
│  │ • Your OS credential store is corrupted           │  │
│  │ • You want to switch sovereignty modes            │  │
│  │                                                   │  │
│  │ Recovery: `zp recover --biometric-reset`          │  │
│  │ Enter your 24 words → re-enroll → done            │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**Narration cue** (`onboard-recovery.mp3`):
> "One more thing before we continue. Your biometric is powerful because it's uniquely yours — but it can change. Life happens. So ZeroPoint just generated a recovery code: twenty-four words that encode your Genesis secret in human-readable form. Write them down. Print them. Store them somewhere physical, offline, safe. If your biometric ever changes catastrophically — or you move to a new machine, or your credential store gets corrupted — these twenty-four words will reconstruct your entire identity. No server, no cloud backup, no phone call to support. Just your words, your machine, and a fresh biometric enrollment. This is the only time this code will be shown. The button won't work twice."

### Implementation path

**v0.1 (now):** Biometric gating via OS credential store (`kSecAccessControlBiometryCurrentSet` on macOS, fprintd on Linux). The Genesis secret requires biometric to read. Session-scoped — one Touch ID per session.

**v0.2:** Per-action biometric for high-privilege operations. `zp` commands that touch the Genesis secret directly (not just derived vault key) require a fresh biometric proof. WebAuthn/FIDO2 support in the browser UI for the same flow.

**v0.3:** Continuous presence for live agent sessions. Local face presence detection (no cloud, no transmission). Presence attestations in the receipt chain. Governance gates that require `presence_verified: true`.

### Keyring crate integration

The `keyring` crate v3.6.x with `apple-native` feature supports `SecAccessControl`. The change to `save_genesis_to_credential_store()` is:

```rust
// Current: default access control (login password)
let entry = Entry::new("zeropoint", "genesis-secret")?;
entry.set_password(&hex::encode(secret))?;

// Biometric: Secure Enclave gated
// Requires Security framework bindings (security-framework crate)
let access_control = SecAccessControl::create_with_flags(
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    SecAccessControlCreateFlags::BiometryCurrentSet,
)?;
// Store via Security framework directly with access control
SecItemAdd(query_with_access_control)?;
```

On Linux, fprintd integration requires `polkit` authentication. The keyring crate's `sync-secret-service` feature handles the Secret Service API, but biometric gating requires wrapping the vault access call with an fprintd verify:

```rust
// Before accessing Secret Service, verify biometric
Command::new("fprintd-verify")
    .arg(&username)
    .status()?;
// Then proceed with normal Secret Service access
```

---

## Implementation Order

1. **Platform detection + biometric probe** — detect Touch ID, Face ID, fprintd availability at server startup
2. **Biometric-gated credential store** — `save_genesis_to_credential_store()` with `kSecAccessControlBiometryCurrentSet` on macOS, fprintd verify on Linux
3. **Server-side WebSocket endpoint** (`/api/onboard/ws`) — wraps existing `init.rs`, `configure.rs`, and vault operations, with sovereignty mode parameter
4. **Static HTML/CSS/JS** — single `onboard.html` page with all 7 steps, reusing setup.html design components
5. **Narration script writing** — the exact text for each MP3 (drafts above)
6. **Narration recording** — 8 MP3 files, ~3.5 minutes total
7. **Integration testing** — run through the full flow on macOS (Touch ID) and Linux (fprintd + password fallback)
8. **CLI fallback** — update `zp onboard` wizard with sovereignty mode selection

---

## What This Replaces

Before this page exists, the onboarding flow is:
```
zp init → zp configure scan → zp configure vault-add (×N) → zp configure auto
```
Four separate commands, each requiring the user to know what comes next.

After this page exists, the onboarding flow is:
```
zp serve → open localhost:3000/onboard → click through 6 narrated steps
```
One command, one browser tab, guided the entire way.

The CLI `zp onboard` wizard (already built) becomes the fallback for headless environments. Same flow, text-only interface, same underlying operations.
