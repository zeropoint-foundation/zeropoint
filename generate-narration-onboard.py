#!/usr/bin/env python3
"""
generate-narration-onboard.py — Onboarding narration script generator
Produces narration-script-onboard.txt and generate-audio-onboard.sh
for Piper TTS with dual voices: Amy (even steps) and Kusal (odd steps + recovery).

Usage: cd ~/projects/zeropoint && python3 generate-narration-onboard.py
Then:  bash generate-audio-onboard.sh
"""

import os
from pathlib import Path

# ─── Configuration ───────────────────────────────────────────────
OUTPUT_SCRIPT = "narration-script-onboard.txt"
OUTPUT_AUDIO_SH = "generate-audio-onboard.sh"
AUDIO_DIR = "assets/narration/onboard"  # Relative to project root; deployed to ~/.zeropoint/assets/ by zp-dev.sh

PIPER_BIN = "/Users/kenrom/anaconda3/bin/piper"
PIPER_MODEL_DIR = "/Users/kenrom/projects/zeropoint/models/piper"

# ─── Voice profiles ──────────────────────────────────────────────
# Amy:   even steps (0, 2, 4, 6, 8)
# Kusal: odd steps  (1, 3, 5, 7) + recovery
VOICES = {
    "kusal": {
        "voice": "kusal",
        "length_scale": 0.8097,   # 1/1.235 = ~1.24x speed (5% slower than 1.30x)
        "noise_scale": 0.360,
        "noise_w": 0.650,         # reduced from 0.930 for clearer articulation
        "sentence_silence": 0.30,
    },
    "amy": {
        "voice": "amy",
        "length_scale": 0.7692,   # 1/1.30 = 1.30x speed
        "noise_scale": 0.360,
        "noise_w": 0.930,
        "sentence_silence": 0.30,
    },
}

# Step-to-voice mapping: even steps → Amy, odd steps + recovery → Kusal
STEP_VOICE = {
    "onboard-welcome.mp3": "amy",          # Step 0 (even)
    "onboard-sovereignty.mp3": "kusal",    # Step 1 (odd)
    "onboard-genesis.mp3": "amy",          # Step 2 (even)
    "onboard-recovery.mp3": "kusal",       # Recovery (special)
    "onboard-vault.mp3": "kusal",          # Step 3 (odd)
    "onboard-inference.mp3": "amy",        # Step 4 (even)
    "onboard-discover.mp3": "kusal",       # Step 5 (odd)
    "onboard-credentials.mp3": "amy",      # Step 6 (even)
    "onboard-configure.mp3": "kusal",      # Step 7 (odd)
    "onboard-complete.mp3": "amy",         # Step 8 (even)
}

# Legacy single-voice defaults (used if STEP_VOICE entry missing)
PIPER_VOICE = "kusal"
PIPER_LENGTH_SCALE = 0.7692
PIPER_NOISE_SCALE = 0.360
PIPER_NOISE_W = 0.930
PIPER_SENTENCE_SILENCE = 0.30

# ─── Narration Scripts ───────────────────────────────────────────
# Each entry: (filename, narration_text)
# These match the design doc: docs/design/onboard-browser-ux.md

NARRATIONS = [
    (
        "onboard-welcome.mp3",
        "Welcome to ZeroPoint. Before we begin, let's be clear about what's "
        "happening here, and why it matters. "
        "Right now, your digital identity is issued by institutions. Your "
        "credentials are stored by platforms. Your trust depends on "
        "infrastructure you don't control. "
        "That worked when humans were the only actors. But we're entering "
        "the Agentic Age, where autonomous agents act on your behalf, "
        "making decisions, calling APIs, moving data. Those agents inherit "
        "whatever trust model you're using. If your keys live on someone "
        "else's server, your agents answer to someone else's rules. "
        "In order to live free, you must take agency and responsibility "
        "for your own information. Otherwise, you will be owned. "
        "That's what the next few minutes are about. We're going to create "
        "your cryptographic root of trust, a single key that everything "
        "derives from. Your vault, your governance policies, your agent "
        "certificates, all yours. Let's begin."
    ),
    (
        "onboard-sovereignty.mp3",
        "This is the most important decision in your setup. "
        "Your Genesis secret, the root of all trust, needs a guardian "
        "that answers only to you. Not a password in a database. Not a "
        "token from an OAuth provider. Something that proves you are present. "
        "Every key stored by a platform is a key someone else can revoke, "
        "surveil, or lose in a breach. Every agent that inherits those "
        "credentials inherits that vulnerability. In the Agentic Age, the "
        "trust model you choose isn't just personal security. It's the "
        "foundation your AI agents stand on. "
        "That's why biometric and hardware options are front and center here. "
        "Your fingerprint or face unlocks everything through the Secure "
        "Enclave, a hardware vault on your device that no software can "
        "extract from. No passwords to leak. No tokens to steal. Just you. "
        "Or a hardware wallet, a YubiKey, a Ledger, a Trezor, where the "
        "cryptography happens on the device itself. The key never touches "
        "software. It's derived directly from the hardware. "
        "Privacy by design means your biometric data never leaves your "
        "device. No telemetry, no cloud enrollment, no third-party "
        "verification. Your sovereignty boundary is between you and your "
        "machine. Nothing and no one else. "
        "And if your provider changes? ZeroPoint creates a recovery kit "
        "during genesis. A 24-word mnemonic you print or store offline. "
        "It lets you re-enroll a new provider without losing your "
        "identity. The Genesis secret stays intact. Only the gate in "
        "front of it changes. "
        "Choose a biometric or hardware device if your system supports it. "
        "Login password is a solid starting point, and you can upgrade later "
        "without re-keying. File-based is for servers and CI only."
    ),
    (
        "onboard-genesis.mp3",
        "What just happened is something that's never happened to most "
        "people before. You created your own root of trust. "
        "In the old model, your digital identity is issued to you, by a "
        "company, a government, a platform. They hold the master copy. "
        "They can revoke it. You are a tenant in their system. "
        "What ZeroPoint just created is different. This is an Ed25519 "
        "keypair, the same cryptography that secures SSH, TLS, and digital "
        "signatures worldwide, but it wasn't issued by anyone. You "
        "generated it. You hold the only copy of the secret half. "
        "It's sealed in your operating system's credential store, gated "
        "by the sovereignty boundary you chose. "
        "Your Operator key was derived from this Genesis key. Both are "
        "in a certificate chain, like TLS but for your identity, signed "
        "by you. Nobody else has a copy. Nobody can revoke it. Nobody "
        "even needs to know it exists, until you choose to prove "
        "something with it. "
        "That's the shift. From identity as a service, to identity as "
        "a property right. "
        "For now, this key is local. Only you know it exists. But later, "
        "if you choose, you can anchor it to a public ledger, and "
        "everything changes. Your agents can prove who they work for. "
        "Other agents can verify your governance before trusting you. "
        "That's Act 3. We'll get there."
    ),
    (
        "onboard-recovery.mp3",
        "ZeroPoint just generated a recovery kit. These 24 words encode "
        "your Genesis secret using BIP-39, the same standard used by "
        "cryptocurrency wallets worldwide. Write them down. Store them "
        "offline. A safe, a lockbox, a sealed envelope with someone you "
        "trust. Never type them into a computer unless you need to "
        "recover. If you lose both your sovereignty provider and these "
        "words, your Genesis key is gone. This screen will not appear "
        "again."
    ),
    (
        "onboard-vault.mp3",
        "Think about where your API keys exist right now. In a dot-env "
        "file. In a password manager run by a company. In a cloud "
        "provider's secrets manager. In every case, someone else's "
        "infrastructure sits between you and your credentials. If that "
        "infrastructure is breached, your keys are exposed. If that "
        "company changes terms, your access can be cut. "
        "ZeroPoint's vault is different. Every API key you're about to "
        "add gets encrypted with a vault key derived from your Genesis "
        "secret, the key you just created and that only you control. "
        "The derivation uses BLAKE3, keyed with a domain separator so "
        "the vault key can never collide with anything else. The vault "
        "key only exists in memory while it's being used, then it's "
        "zeroized, overwritten with zeros. "
        "No cloud. No third party. No infrastructure that isn't yours. "
        "Your Genesis key is your credential. If you move to a new "
        "machine, you export an encrypted vault backup and re-derive "
        "on the other side. Your credentials travel with you because "
        "they belong to you."
    ),
    (
        "onboard-inference.mp3",
        "Here's a sovereignty question most onboarding flows never ask. "
        "Where does your inference run? "
        "Every time you prompt a cloud model, OpenAI, Anthropic, Google, "
        "your data, your reasoning, your chain-of-thought is sent to "
        "someone else's hardware. They see everything. They meter it. "
        "They set the terms. "
        "That's fine when you need frontier capability. But for routine "
        "tasks, summarization, code completion, local analysis, do you "
        "really need to send that data across the wire? "
        "Local inference changes the equation. ZeroPoint just scanned "
        "your system, your hardware, your memory, your GPU, and checked "
        "whether a local runtime is already running. "
        "If you have one, great. If not, we'll walk you through the "
        "setup right here. Choose a runtime, Ollama, LM Studio, Jan, "
        "whatever fits your workflow, and ZeroPoint gives you the exact "
        "install commands for your platform, recommends a model that "
        "fits your hardware, and tells you why. Every recommendation "
        "links to its source. You can verify it yourself. That's how "
        "this should work. "
        "Mixed mode is the sweet spot for most people. Local models "
        "handle the routine work. Cloud models handle what requires "
        "frontier capability. And your governance proxy decides which "
        "is which, based on rules you define. "
        "If you'd rather skip this for now, that's fine too. Choose "
        "cloud or mixed below and add local inference anytime with "
        "zp configure inference."
    ),
    (
        "onboard-discover.mp3",
        "ZeroPoint just scanned your project directories for AI tools. "
        "It looks at dot-env-example files, the templates that tools ship "
        "with, and maps each environment variable to a credential in your "
        "vault. The key insight is deduplication. If three tools all need "
        "an OpenAI API key, that's one credential stored once, injected "
        "three times. The next step collects only the unique keys you "
        "actually need."
    ),
    (
        "onboard-credentials.mp3",
        "Now we add your API keys. But notice how this is different from "
        "what you're used to. Normally, you'd paste an API key into a "
        "dot-env file, or hand it to a secrets manager run by a cloud "
        "provider. The key sits in plaintext on disk, or in someone "
        "else's infrastructure. If the machine is compromised, or the "
        "provider is breached, your keys are exposed. "
        "Here, the moment you press Store, two things happen. First, the "
        "key is encrypted in your vault. ChaCha20-Poly1305, authenticated "
        "encryption, using a key derived from the Genesis secret that only "
        "you control. The plaintext never touches disk. It goes straight "
        "from this page to your local vault over a local WebSocket "
        "connection. No cloud. No intermediary. "
        "Second, ZeroPoint validates the key in real time. A lightweight "
        "health check reaches out to the provider's API and confirms "
        "the credential is live. You'll see a green check for valid keys, "
        "a red mark for rejected ones, and a warning for anything "
        "unreachable. By the time you leave this step, you know exactly "
        "which credentials are working and which need attention. "
        "If you don't have a key yet, skip it. You can always add it "
        "later with zp configure vault-add."
    ),
    (
        "onboard-configure.mp3",
        "This is where Act 2 begins. Governance, with verified credentials. "
        "Before configuration starts, ZeroPoint runs a full health check "
        "across every credential in your vault. Each stored key is tested "
        "against its provider in real time. You'll see which credentials "
        "are live, which are rejected, and which services can't be reached. "
        "This isn't a formality. You're about to route real API calls "
        "through governance. You need to know the credentials you're "
        "injecting actually work. "
        "In the old model, you give API keys to tools and hope for the "
        "best. You have no visibility into what calls are being made, "
        "no way to enforce limits, no audit trail. If an agent goes "
        "rogue, you find out when the bill arrives, or when the damage "
        "is done. "
        "ZeroPoint changes this. If you enable the governance proxy, "
        "every API call from your tools routes through your local "
        "policy engine. Your tools think they're talking directly to "
        "OpenAI or Anthropic, but every request is checked against "
        "your governance gates, metered for cost, and stamped with a "
        "signed receipt that chains cryptographically to the one before "
        "it. "
        "This isn't surveillance. It's awareness. You can't govern what "
        "you can't see. "
        "You can turn this on now or add it later with zp proxy start. "
        "Either way, your credentials are verified and secured in your "
        "vault."
    ),
    (
        "onboard-complete.mp3",
        "Let's take stock of what you've built. "
        "You created your own cryptographic root of trust. Not issued "
        "by anyone. Not stored on anyone's server. You encrypted your "
        "credentials in a vault that only you can unlock. You configured "
        "your tools to route through a governance proxy that enforces "
        "your rules. Every API call produces a signed receipt. Every "
        "receipt chains to the one before it. The chain becomes proof. "
        "This is Acts 1 and 2 complete. Sovereignty and governance. "
        "Now, remember what I said about Act 3? Public attestation. "
        "Here's what it unlocks. Your agents can prove who they work "
        "for. When your agent contacts another agent, that agent can "
        "cryptographically verify your identity and governance posture "
        "before trusting anything. Your governance chain becomes a "
        "track record, a reputation that can't be faked because every "
        "receipt is hash-chained to the one before it. And in multi-agent "
        "workflows, peers can verify each other's policies before "
        "sharing data. No central authority deciding who's trustworthy. "
        "Just math. "
        "Anchoring is irreversible. Once your Genesis is on a public "
        "ledger, it's permanent. ZeroPoint doesn't push you there. "
        "You go when you're ready. "
        "For now, run zp status to verify everything, zp secure to wrap "
        "your shell and AI tools, or zp audit log to see your receipt "
        "chain. "
        "And one last thing. "
        "Thank you. For choosing to live sovereign. You've taken on "
        "the responsibility, and the power, of owning your own trust. "
        "Not everyone will. But you did, and that matters. "
        "Now build a better world. The kind you want to live in."
    ),
]


def main():
    # ─── Generate narration-script-onboard.txt ─────────────────
    lines = []
    lines.append("=" * 70)
    lines.append("ZEROPOINT ONBOARDING — NARRATION SCRIPT")
    lines.append("Dual voice: Amy (even steps) + Kusal (odd steps + recovery)")
    lines.append("Generated for Piper TTS")
    lines.append("=" * 70)
    lines.append("")

    for filename, text in NARRATIONS:
        voice_name = STEP_VOICE.get(filename, "kusal")
        lines.append(f"--- {filename} [{voice_name}] ---")
        lines.append(text)
        lines.append("")

    lines.append(f"Total: {len(NARRATIONS)} narration files")

    with open(OUTPUT_SCRIPT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Written: {OUTPUT_SCRIPT} ({len(NARRATIONS)} narrations)")

    # ─── Collect unique voices used ──────────────────────────────
    used_voices = sorted(set(
        STEP_VOICE.get(fn, "kusal") for fn, _ in NARRATIONS
    ))

    # ─── Generate generate-audio-onboard.sh ─────────────────────
    sh = []
    sh.append("#!/usr/bin/env bash")
    sh.append("#")
    sh.append("# generate-audio-onboard.sh — Produce onboarding narration via Piper TTS")
    sh.append("# Dual voice: Amy (even steps) / Kusal (odd steps + recovery)")
    sh.append(f"# Total: {len(NARRATIONS)} narration files")
    sh.append("# Usage: cd ~/projects/zeropoint && bash generate-audio-onboard.sh")
    sh.append("#")
    sh.append(f'PIPER="{PIPER_BIN}"')
    sh.append(f'MODEL_DIR="{PIPER_MODEL_DIR}"')
    sh.append('AUDIO_DIR="$(cd "$(dirname "$0")" && pwd)/assets/narration/onboard"')
    sh.append('SKIP_EXISTING="${SKIP_EXISTING:-0}"')
    sh.append("")

    # ── Resolve model file for each voice ──
    for v in used_voices:
        var = f"MODEL_{v.upper()}"
        sh.append(f'{var}=$(ls "$MODEL_DIR"/*"{v}"*.onnx 2>/dev/null | head -1)')
        sh.append(f'if [ -z "${var}" ]; then')
        sh.append(f'  echo "ERROR: No .onnx model matching \\"{v}\\" found in $MODEL_DIR"')
        dl_name = f"en_US-{v}-medium"
        sh.append(f'  echo "Download: https://huggingface.co/rhasspy/piper-voices/tree/main/en/en_US/{v}/medium"')
        sh.append(f'  exit 1')
        sh.append(f'fi')
        sh.append(f'echo "Voice {v}: ${var}"')
        sh.append("")

    sh.append('mkdir -p "$AUDIO_DIR"')
    sh.append("")
    sh.append("generated=0")
    sh.append("skipped=0")
    sh.append("failed=0")
    sh.append("")

    # ── generate() now accepts model path + voice params ──
    sh.append('generate() {')
    sh.append('  local filename="$1"')
    sh.append('  local text="$2"')
    sh.append('  local model="$3"')
    sh.append('  local length_scale="$4"')
    sh.append('  local noise_scale="$5"')
    sh.append('  local noise_w="$6"')
    sh.append('  local sentence_silence="$7"')
    sh.append('  local outpath="$AUDIO_DIR/$filename"')
    sh.append('')
    sh.append('  if [ "$SKIP_EXISTING" = "1" ] && [ -f "$outpath" ]; then')
    sh.append('    skipped=$((skipped + 1))')
    sh.append('    return')
    sh.append('  fi')
    sh.append('')
    sh.append('  echo "Generating: $filename"')
    sh.append('  echo "$text" | "$PIPER" --model "$model" '
              '--length_scale "$length_scale" '
              '--noise_scale "$noise_scale" '
              '--noise_w "$noise_w" '
              '--sentence_silence "$sentence_silence" '
              '--output_file "$outpath" 2>/dev/null')
    sh.append('  if [ $? -eq 0 ]; then')
    sh.append('    generated=$((generated + 1))')
    sh.append('  else')
    sh.append('    echo "  FAILED: $filename"')
    sh.append('    failed=$((failed + 1))')
    sh.append('  fi')
    sh.append('}')
    sh.append("")

    # ── Per-file calls with voice-specific model + params ──
    for filename, text in NARRATIONS:
        voice_name = STEP_VOICE.get(filename, "kusal")
        profile = VOICES.get(voice_name, VOICES["kusal"])
        model_var = f"$MODEL_{voice_name.upper()}"
        escaped = text.replace("'", "'\\''")
        sh.append(
            f"generate '{filename}' '{escaped}' "
            f'"{model_var}" '
            f"{profile['length_scale']} "
            f"{profile['noise_scale']} "
            f"{profile['noise_w']} "
            f"{profile['sentence_silence']}"
        )

    sh.append("")
    sh.append('echo ""')
    sh.append('echo "Done. Generated: $generated, Skipped: $skipped, Failed: $failed"')
    sh.append('echo "Audio dir: $AUDIO_DIR"')

    with open(OUTPUT_AUDIO_SH, "w", encoding="utf-8") as f:
        f.write("\n".join(sh))
    os.chmod(OUTPUT_AUDIO_SH, 0o755)
    print(f"Written: {OUTPUT_AUDIO_SH}")
    print(f"\nWorkflow:")
    print(f"  1. Review {OUTPUT_SCRIPT} for accuracy")
    print(f"  2. Run: bash {OUTPUT_AUDIO_SH}")
    print(f"     Or:  SKIP_EXISTING=1 bash {OUTPUT_AUDIO_SH}")
    print(f"\nVoice models required in {PIPER_MODEL_DIR}:")
    for v in used_voices:
        print(f"  - en_US-{v}-medium (*.onnx + *.onnx.json)")


if __name__ == "__main__":
    main()
