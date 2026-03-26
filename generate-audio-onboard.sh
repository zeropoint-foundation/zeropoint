#!/usr/bin/env bash
#
# generate-audio-onboard.sh — Produce onboarding narration via Piper TTS
# Dual voice: Amy (even steps) / Kusal (odd steps + recovery)
# Total: 10 narration files
# Usage: cd ~/projects/zeropoint && bash generate-audio-onboard.sh
#
PIPER="/Users/kenrom/anaconda3/bin/piper"
MODEL_DIR="/Users/kenrom/projects/zeropoint/models/piper"
AUDIO_DIR="$(cd "$(dirname "$0")" && pwd)/assets/narration/onboard"
SKIP_EXISTING="${SKIP_EXISTING:-0}"

MODEL_AMY=$(ls "$MODEL_DIR"/*"amy"*.onnx 2>/dev/null | head -1)
if [ -z "$MODEL_AMY" ]; then
  echo "ERROR: No .onnx model matching \"amy\" found in $MODEL_DIR"
  echo "Download: https://huggingface.co/rhasspy/piper-voices/tree/main/en/en_US/amy/medium"
  exit 1
fi
echo "Voice amy: $MODEL_AMY"

MODEL_KUSAL=$(ls "$MODEL_DIR"/*"kusal"*.onnx 2>/dev/null | head -1)
if [ -z "$MODEL_KUSAL" ]; then
  echo "ERROR: No .onnx model matching \"kusal\" found in $MODEL_DIR"
  echo "Download: https://huggingface.co/rhasspy/piper-voices/tree/main/en/en_US/kusal/medium"
  exit 1
fi
echo "Voice kusal: $MODEL_KUSAL"

mkdir -p "$AUDIO_DIR"

generated=0
skipped=0
failed=0

generate() {
  local filename="$1"
  local text="$2"
  local model="$3"
  local length_scale="$4"
  local noise_scale="$5"
  local noise_w="$6"
  local sentence_silence="$7"
  local outpath="$AUDIO_DIR/$filename"

  if [ "$SKIP_EXISTING" = "1" ] && [ -f "$outpath" ]; then
    skipped=$((skipped + 1))
    return
  fi

  echo "Generating: $filename"
  echo "$text" | "$PIPER" --model "$model" --length_scale "$length_scale" --noise_scale "$noise_scale" --noise_w "$noise_w" --sentence_silence "$sentence_silence" --output_file "$outpath" 2>/dev/null
  if [ $? -eq 0 ]; then
    generated=$((generated + 1))
  else
    echo "  FAILED: $filename"
    failed=$((failed + 1))
  fi
}

generate 'onboard-welcome.mp3' 'Welcome to ZeroPoint. Before we begin, let'\''s be clear about what'\''s happening here, and why it matters. Right now, your digital identity is issued by institutions. Your credentials are stored by platforms. Your trust depends on infrastructure you don'\''t control. That worked when humans were the only actors. But we'\''re entering the Agentic Age, where autonomous agents act on your behalf, making decisions, calling APIs, moving data. Those agents inherit whatever trust model you'\''re using. If your keys live on someone else'\''s server, your agents answer to someone else'\''s rules. In order to live free, you must take agency and responsibility for your own information. Otherwise, you will be owned. That'\''s what the next few minutes are about. We'\''re going to create your cryptographic root of trust, a single key that everything derives from. Your vault, your governance policies, your agent certificates, all yours. Let'\''s begin.' "$MODEL_AMY" 0.7692 0.36 0.93 0.3
generate 'onboard-sovereignty.mp3' 'Here'\''s the first real departure from the old model. Traditionally, proving your identity means presenting credentials issued by someone else. A password stored in a corporate database. A token granted by an OAuth provider. A certificate signed by a certificate authority. Someone else holds the keys to your identity. They can revoke it, surveil it, or lose it in a breach. ZeroPoint inverts this. Your Genesis secret, the root of your entire trust chain, needs a guardian that answers only to you. A password can be phished, guessed, or stolen from a database. A file on disk can be copied by any process running as your user. But a sovereignty provider? That'\''s yours. A fingerprint, a hardware wallet, Touch ID, a face scan — something that proves you are physically present. An agent running on your machine, no matter how capable, cannot fake that proof. This is what sovereignty-first security looks like in practice. Your physical presence is the boundary between authorized and unauthorized. No institution mediates. No platform can revoke. A Trezor on your desk or Touch ID on your laptop — the form factor changes, but the principle doesn'\''t. You prove presence. ZeroPoint trusts the proof. And if your provider changes? ZeroPoint creates a recovery kit during genesis. A 24-word mnemonic you print or store offline. It lets you re-enroll a new provider without losing your identity. The Genesis secret stays intact. Only the gate in front of it changes. Choose a hardware device or biometric if your system supports it. Login password is the solid default. File-based is for servers and CI.' "$MODEL_KUSAL" 0.8097 0.36 0.65 0.3
generate 'onboard-genesis.mp3' 'What just happened is something that'\''s never happened to most people before. You created your own root of trust. In the old model, your digital identity is issued to you, by a company, a government, a platform. They hold the master copy. They can revoke it. You are a tenant in their system. What ZeroPoint just created is different. This is an Ed25519 keypair, the same cryptography that secures SSH, TLS, and digital signatures worldwide, but it wasn'\''t issued by anyone. You generated it. You hold the only copy of the secret half. It'\''s sealed in your operating system'\''s credential store, gated by the sovereignty boundary you chose. Your Operator key was derived from this Genesis key. Both are in a certificate chain, like TLS but for your identity, signed by you. Nobody else has a copy. Nobody can revoke it. Nobody even needs to know it exists, until you choose to prove something with it. That'\''s the shift. From identity as a service, to identity as a property right. For now, this key is local. Only you know it exists. But later, if you choose, you can anchor it to a public ledger, and everything changes. Your agents can prove who they work for. Other agents can verify your governance before trusting you. That'\''s Act 3. We'\''ll get there.' "$MODEL_AMY" 0.7692 0.36 0.93 0.3
generate 'onboard-recovery.mp3' 'ZeroPoint just generated a recovery kit. These 24 words encode your Genesis secret using BIP-39, the same standard used by cryptocurrency wallets worldwide. Write them down. Store them offline. A safe, a lockbox, a sealed envelope with someone you trust. Never type them into a computer unless you need to recover. If you lose both your sovereignty provider and these words, your Genesis key is gone. This screen will not appear again.' "$MODEL_KUSAL" 0.8097 0.36 0.65 0.3
generate 'onboard-vault.mp3' 'Think about where your API keys exist right now. In a dot-env file. In a password manager run by a company. In a cloud provider'\''s secrets manager. In every case, someone else'\''s infrastructure sits between you and your credentials. If that infrastructure is breached, your keys are exposed. If that company changes terms, your access can be cut. ZeroPoint'\''s vault is different. Every API key you'\''re about to add gets encrypted with a vault key derived from your Genesis secret, the key you just created and that only you control. The derivation uses BLAKE3, keyed with a domain separator so the vault key can never collide with anything else. The vault key only exists in memory while it'\''s being used, then it'\''s zeroized, overwritten with zeros. No cloud. No third party. No infrastructure that isn'\''t yours. Your Genesis key is your credential. If you move to a new machine, you export an encrypted vault backup and re-derive on the other side. Your credentials travel with you because they belong to you.' "$MODEL_KUSAL" 0.8097 0.36 0.65 0.3
generate 'onboard-inference.mp3' 'Here'\''s a sovereignty question most onboarding flows never ask. Where does your inference run? Every time you prompt a cloud model, OpenAI, Anthropic, Google, your data, your reasoning, your chain-of-thought is sent to someone else'\''s hardware. They see everything. They meter it. They set the terms. That'\''s fine when you need frontier capability. But for routine tasks, summarization, code completion, local analysis, do you really need to send that data across the wire? Local inference changes the equation. ZeroPoint just scanned your system, your hardware, your memory, your GPU, and checked whether a local runtime is already running. If you have one, great. If not, we'\''ll walk you through the setup right here. Choose a runtime, Ollama, LM Studio, Jan, whatever fits your workflow, and ZeroPoint gives you the exact install commands for your platform, recommends a model that fits your hardware, and tells you why. Every recommendation links to its source. You can verify it yourself. That'\''s how this should work. Mixed mode is the sweet spot for most people. Local models handle the routine work. Cloud models handle what requires frontier capability. And your governance proxy decides which is which, based on rules you define. If you'\''d rather skip this for now, that'\''s fine too. Choose cloud or mixed below and add local inference anytime with zp configure inference.' "$MODEL_AMY" 0.7692 0.36 0.93 0.3
generate 'onboard-discover.mp3' 'ZeroPoint just scanned your project directories for AI tools. It looks at dot-env-example files, the templates that tools ship with, and maps each environment variable to a credential in your vault. The key insight is deduplication. If three tools all need an OpenAI API key, that'\''s one credential stored once, injected three times. The next step collects only the unique keys you actually need.' "$MODEL_KUSAL" 0.8097 0.36 0.65 0.3
generate 'onboard-credentials.mp3' 'Now we add your API keys. But notice how this is different from what you'\''re used to. Normally, you'\''d paste an API key into a dot-env file, or hand it to a secrets manager run by a cloud provider. The key sits in plaintext on disk, or in someone else'\''s infrastructure. If the machine is compromised, or the provider is breached, your keys are exposed. Here, the moment you press Store, two things happen. First, the key is encrypted in your vault. ChaCha20-Poly1305, authenticated encryption, using a key derived from the Genesis secret that only you control. The plaintext never touches disk. It goes straight from this page to your local vault over a local WebSocket connection. No cloud. No intermediary. Second, ZeroPoint validates the key in real time. A lightweight health check reaches out to the provider'\''s API and confirms the credential is live. You'\''ll see a green check for valid keys, a red mark for rejected ones, and a warning for anything unreachable. By the time you leave this step, you know exactly which credentials are working and which need attention. If you don'\''t have a key yet, skip it. You can always add it later with zp configure vault-add.' "$MODEL_AMY" 0.7692 0.36 0.93 0.3
generate 'onboard-configure.mp3' 'This is where Act 2 begins. Governance, with verified credentials. Before configuration starts, ZeroPoint runs a full health check across every credential in your vault. Each stored key is tested against its provider in real time. You'\''ll see which credentials are live, which are rejected, and which services can'\''t be reached. This isn'\''t a formality. You'\''re about to route real API calls through governance. You need to know the credentials you'\''re injecting actually work. In the old model, you give API keys to tools and hope for the best. You have no visibility into what calls are being made, no way to enforce limits, no audit trail. If an agent goes rogue, you find out when the bill arrives, or when the damage is done. ZeroPoint changes this. If you enable the governance proxy, every API call from your tools routes through your local policy engine. Your tools think they'\''re talking directly to OpenAI or Anthropic, but every request is checked against your governance gates, metered for cost, and stamped with a signed receipt that chains cryptographically to the one before it. This isn'\''t surveillance. It'\''s awareness. You can'\''t govern what you can'\''t see. You can turn this on now or add it later with zp proxy start. Either way, your credentials are verified and secured in your vault.' "$MODEL_KUSAL" 0.8097 0.36 0.65 0.3
generate 'onboard-complete.mp3' 'Let'\''s take stock of what you'\''ve built. You created your own cryptographic root of trust. Not issued by anyone. Not stored on anyone'\''s server. You encrypted your credentials in a vault that only you can unlock. You configured your tools to route through a governance proxy that enforces your rules. Every API call produces a signed receipt. Every receipt chains to the one before it. The chain becomes proof. This is Acts 1 and 2 complete. Sovereignty and governance. Now, remember what I said about Act 3? Public attestation. Here'\''s what it unlocks. Your agents can prove who they work for. When your agent contacts another agent, that agent can cryptographically verify your identity and governance posture before trusting anything. Your governance chain becomes a track record, a reputation that can'\''t be faked because every receipt is hash-chained to the one before it. And in multi-agent workflows, peers can verify each other'\''s policies before sharing data. No central authority deciding who'\''s trustworthy. Just math. Anchoring is irreversible. Once your Genesis is on a public ledger, it'\''s permanent. ZeroPoint doesn'\''t push you there. You go when you'\''re ready. For now, run zp status to verify everything, zp secure to wrap your shell and AI tools, or zp audit log to see your receipt chain. And one last thing. Thank you. For choosing to live sovereign. You'\''ve taken on the responsibility, and the power, of owning your own trust. Not everyone will. But you did, and that matters. Now build a better world. The kind you want to live in.' "$MODEL_AMY" 0.7692 0.36 0.93 0.3

echo ""
echo "Done. Generated: $generated, Skipped: $skipped, Failed: $failed"
echo "Audio dir: $AUDIO_DIR"