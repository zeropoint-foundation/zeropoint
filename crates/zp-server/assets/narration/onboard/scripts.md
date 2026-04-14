# ZeroPoint Onboard — Narration Scripts

Source text for Piper TTS generation. The canonical pipeline is:

    cd ~/projects/zeropoint
    python3 generate-narration-onboard.py   # produces generate-audio-onboard.sh
    bash generate-audio-onboard.sh          # renders MP3s via Piper

Voices: Amy (even steps) / Kusal (odd steps + recovery)
Tuning: 1.30x speed, noise_scale 0.360, noise_w 0.930, sentence_silence 0.30

These scripts should stay in sync with the NARRATIONS list in
`generate-narration-onboard.py` — that file is the actual source of truth
for audio generation. This file exists as a readable reference.

---

## onboard-welcome.mp3 [amy]

Every API key you've ever used was a borrowed secret. Copied into .env files. Stored in plaintext. Shared across tools you didn't build, on infrastructure you don't control. In the Agentic Age, that model doesn't just leak credentials — it leaks sovereignty. What you're about to do is different. You're going to create your own cryptographic root of trust. Your own vault. Your own governance. And it starts right now, in under five minutes.

---

## onboard-sovereignty.mp3 [kusal]

This is the most important decision in your setup. Your Genesis secret, the root of all trust, needs a guardian that answers only to you. Not a password in a database. Not a token from an OAuth provider. Something that proves you are present. Every key stored by a platform is a key someone else can revoke, surveil, or lose in a breach. Every agent that inherits those credentials inherits that vulnerability. In the Agentic Age, the trust model you choose isn't just personal security. It's the foundation your AI agents stand on. That's why biometric and hardware options are front and center here. Your fingerprint or face unlocks everything through the Secure Enclave, a hardware vault on your device that no software can extract from. No passwords to leak. No tokens to steal. Just you. Or a hardware wallet, a YubiKey, a Ledger, a Trezor, where the cryptography happens on the device itself. The key never touches software. It's derived directly from the hardware. Privacy by design means your biometric data never leaves your device. No telemetry, no cloud enrollment, no third-party verification. Your sovereignty boundary is between you and your machine. Nothing and no one else. And if your provider changes? ZeroPoint creates a recovery kit during genesis. A 24-word mnemonic you print or store offline. It lets you re-enroll a new provider without losing your identity. The Genesis secret stays intact. Only the gate in front of it changes. Choose a biometric or hardware device if your system supports it. Login password is a solid starting point, and you can upgrade later without re-keying. File-based is for servers and CI only.

---

## onboard-genesis.mp3 [amy]

This is the Genesis Ceremony. You're creating an Ed25519 keypair — a public key that identifies you, and a private key that proves it's really you. This isn't issued by an authority. There's no certificate chain leading back to a corporation. You are the root. The Genesis secret is sealed in your OS credential store, gated by whatever sovereignty boundary you chose. From this one key, ZeroPoint derives everything — your vault encryption key, your operator certificate, your governance chain. One secret. Deterministic derivation. No passwords to manage, no tokens to rotate.

---

## onboard-vault.mp3 [kusal]

Your vault replaces every .env file, every password manager entry, every cloud secrets service you've been trusting with your API keys. Here's how it works. Your Genesis secret — the one locked behind your sovereignty provider — is used to derive a vault key through BLAKE3 keyed hashing. That vault key encrypts every credential you store using ChaCha20-Poly1305 authenticated encryption. The vault key is ephemeral — it exists only in memory, derived on demand, then wiped. There's nothing to remember, nothing to back up, nothing to rotate. Your credentials are encrypted at rest, on your machine, under your control.

---

## onboard-inference.mp3 [amy]

Where your inference runs is a sovereignty decision, not just a performance one. Local models keep everything on your hardware — your prompts, your data, your chain of thought never leave the machine. Cloud models give you access to frontier capability, but every call passes through a governance proxy that enforces your policies. Mixed mode — the recommended default — gives you both. Routine tasks stay local. Frontier tasks go to the cloud. And your governance proxy routes each call based on rules you define.

---

## onboard-discover.mp3 [kusal]

ZeroPoint scans your project directories for AI tools — anything with a .env.example file that defines credential requirements. Each tool it finds becomes a candidate for governance. The scan identifies which providers each tool needs, which credentials are already present, and which are missing. This is the bridge between discovery and configuration — once you know what your tools need, you can supply the credentials and bring them under governance.

---

## onboard-credentials.mp3 [amy]

Now we add your API keys. But notice how this is different from what you're used to. Normally, you'd paste an API key into a dot-env file, or hand it to a secrets manager run by a cloud provider. The key sits in plaintext on disk, or in someone else's infrastructure. If the machine is compromised, or the provider is breached, your keys are exposed. Here, the moment you press Store, two things happen. First, the key is encrypted in your vault. ChaCha20-Poly1305, authenticated encryption, using a key derived from the Genesis secret that only you control. The plaintext never touches disk. It goes straight from this page to your local vault over a local WebSocket connection. No cloud. No intermediary. Second, ZeroPoint validates the key in real time. A lightweight health check reaches out to the provider's API and confirms the credential is live. You'll see a green check for valid keys, a red mark for rejected ones, and a warning for anything unreachable. By the time you leave this step, you know exactly which credentials are working and which need attention. If you don't have a key yet, skip it. You can always add it later with zp configure vault-add.

---

## onboard-configure.mp3 [kusal]

This is where Act 2 begins. Governance, with verified credentials. Before configuration starts, ZeroPoint runs a full health check across every credential in your vault. Each stored key is tested against its provider in real time. You'll see which credentials are live, which are rejected, and which services can't be reached. This isn't a formality. You're about to route real API calls through governance. You need to know the credentials you're injecting actually work. In the old model, you give API keys to tools and hope for the best. You have no visibility into what calls are being made, no way to enforce limits, no audit trail. If an agent goes rogue, you find out when the bill arrives, or when the damage is done. ZeroPoint changes this. If you enable the governance proxy, every API call from your tools routes through your local policy engine. Your tools think they're talking directly to OpenAI or Anthropic, but every request is checked against your governance gates, metered for cost, and stamped with a signed receipt that chains cryptographically to the one before it. This isn't surveillance. It's awareness. You can't govern what you can't see. You can turn this on now or add it later with zp proxy start. Either way, your credentials are verified and secured in your vault.

---

## onboard-complete.mp3 [amy]

Look at what you've built. Your own cryptographic identity — not issued, created. A vault that encrypts every credential under keys only you control. A governance proxy that enforces your policies on every API call. Verified credentials that are proven live against their providers. And an attestation chain that's growing with every governed action. Everything is local. Everything is sovereign. Everything is yours. The only question left is whether to anchor it — to make your governance chain publicly verifiable, so your agents can do business with anyone on the network. That's the on-ramp. Your agents are ready.

---

## onboard-recovery.mp3 [kusal]

These twenty-four words are the only way to recover your Genesis secret if you lose access to your sovereignty provider. Write them down — on paper, not in a notes app, not in a screenshot. Store them somewhere physical and secure. This screen will not appear again. If you lose both your provider access and these words, your Genesis key is gone. Your vault contents become unrecoverable. That's not a bug — that's the sovereignty model working as designed. You control the keys. You control the recovery. No one else can help you, and no one else can compromise you.
