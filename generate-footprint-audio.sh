#!/usr/bin/env bash
# generate-footprint-audio.sh — Piper TTS for footprint narration
# Voice: Kusal (en_US-kusal-medium)
# Rate: 1.35x (length_scale = 1/1.35 ≈ 0.7407)
#
# Usage: cd ~/projects/zeropoint && bash generate-footprint-audio.sh
# Requires: piper binary + en_US-kusal-medium model in models/piper/

set -euo pipefail

PIPER="/Users/kenrom/anaconda3/bin/piper"
MODEL_DIR="/Users/kenrom/projects/zeropoint/models/piper"
VOICE="kusal"
MODEL="${MODEL_DIR}/en_US-${VOICE}-medium.onnx"
OUT_DIR="zeropoint.global/assets/narration"

LENGTH_SCALE=0.7407
NOISE_SCALE=0.667
NOISE_W=0.510
SENTENCE_SILENCE=0.30

mkdir -p "$OUT_DIR"

# Check for model
if [ ! -f "$MODEL" ]; then
  echo "Model not found: $MODEL"
  echo "Download from: https://huggingface.co/rhasspy/piper-voices/tree/main/en/en_US/kusal/medium"
  exit 1
fi

generate() {
  local id="$1"
  local text="$2"
  local wav="${OUT_DIR}/${id}.wav"
  local mp3="${OUT_DIR}/${id}.mp3"

  echo "Generating ${id}..."
  echo "$text" | "$PIPER" \
    --model "$MODEL" \
    --length_scale "$LENGTH_SCALE" \
    --noise_scale "$NOISE_SCALE" \
    --noise_w "$NOISE_W" \
    --sentence_silence "$SENTENCE_SILENCE" \
    --output_file "$wav"

  # Convert to mp3
  ffmpeg -y -i "$wav" -codec:a libmp3lame -qscale:a 4 "$mp3" 2>/dev/null
  rm -f "$wav"
  echo "  → ${mp3}"
}

# ─── Identity & Access ───
generate "identity" "Identity and Access. In a world of autonomous agents, the first question is always: who are you, and what are you allowed to do? ZeroPoint answers both cryptographically — and covers this domain completely. Every agent carries an Ed25519 keypair. No request goes unsigned. Authorization isn't static — it's evaluated in real time against policy context and trust tier. Credentials are locked in a vault using ChaCha20-Poly1305 encryption. Each agent is scoped to only the permissions it needs — no more, no less. Those permissions come with expiry dates and delegation depth limits baked in. There are no static secrets to steal — keypairs rotate dynamically throughout their lifecycle. And peer discovery happens through the Presence Plane — dual-backend discovery across a web relay and Reticulum mesh, with reciprocity enforcement and no central registry. Seven for seven. Full coverage."

# ─── Governance & Policy ───
generate "governance" "Governance and Policy. This is where ZeroPoint's constitutional backbone lives — and it's one hundred percent built in. Every action passes through a four-stage Governance Gate: Guard, Policy, Execute, Audit. Nothing slips through unchecked. At the foundation are constitutional rules that can't be removed — the Harm Principle and the Sovereignty Rule. Content is screened against policy before any action is taken. And the human is always the root authority — that's not a suggestion, it's enforced at the protocol level. ZeroPoint's four tenets aren't aspirational guidelines. They're code. And the immutable audit trail means you can prove compliance, not just promise it. Full coverage across the board."

# ─── Audit & Traceability ───
generate "audit" "Audit and Traceability. Trust without evidence is just hope. ZeroPoint provides a tamper-evident, hash-chained record of every action — and covers eighty-three percent of this domain. Every receipt in the chain is signed with Ed25519, so you can prove exactly who did what, and when. The Audit Store runs cryptographic chain verification — if anything's been altered, you'll know. Forensic records capture the complete action history, ready for incident response. Where coverage is partial, it's deliberate. The audit data is there for behavioral analytics, but detection ML is something you layer on top. And posture assessment? ZeroPoint gives you the data — the assessment itself is a human judgment call. Four capabilities fully built in, two enabled and ready to extend."

# ─── Agentic Threats ───
generate "agentic" "Agentic Threats. When agents operate autonomously, the risks are fundamentally different. ZeroPoint was designed for this — and covers eighty-six percent of the domain. Tool misuse? Every skill runs through a verified registry with sandboxed execution. Rogue agents? There's a kill switch backed by the Sovereignty Rule, plus capability revocation. Agent-to-agent communication is secured over the Presence Plane's dual-backend transport — every message is Ed25519-signed whether it travels through the web relay or a Reticulum mesh link. Passive scanning is stopped cold by reciprocity enforcement — peers must announce themselves before they can observe anyone else. Excessive agency is prevented through scoped capabilities and hard delegation depth limits. Where coverage is partial, the defenses are still active. Goal hijacking is constrained by the Governance Gate and policy rules. And cascading hallucinations — the receipt chain traces provenance across agent chains, so you can follow the thread back to the source. Five built in, two partially covered."

# ─── LLM Threats ───
generate "llm" "LLM Threats. These are the top risks for any application built on large language models — and ZeroPoint addresses fifty-six percent of them directly. Sensitive information disclosure is controlled through scoped capability grants. Insecure plugin design is handled by the verified skill registry with sandboxed execution. Unbounded consumption hits hard limits through capability grants with rate and scope controls. Where coverage is partial, the Governance Gate is doing the heavy lifting. It screens for prompt injection — though it's a policy pipeline, not a dedicated web application firewall. Supply chain risk is mitigated through Rust's memory safety and plugin verification in the registry. And policy rules can enforce output screening against prompt leakage. What's outside scope? Data poisoning and model theft. Those are training-time and model-layer concerns — real threats, but not ones a runtime governance framework can solve. Three built in, three partial, two honestly outside scope."

# ─── Adversarial ML ───
generate "atlas" "Adversarial ML. MITRE ATLAS maps the adversarial techniques targeting machine learning systems — from reconnaissance through impact. ZeroPoint covers fifty-six percent of this attack lifecycle. Reconnaissance is now directly addressed — the Presence Plane's reciprocity enforcement makes scanners observable before they can observe anything. You can't quietly probe a ZeroPoint network. Initial access through APIs is locked down with Ed25519 identity and capability grants — you don't get in without cryptographic proof. Exfiltration is caught through scoped access controls backed by audit trail detection. Where coverage is partial, ZeroPoint is still in the fight. The Governance Gate screens for suspicious patterns during attack staging. The kill switch and blast radius minimization limit impact. And capability expiry plus revocation address persistence. What's outside scope is outside scope — attacker infrastructure and model-layer evasion techniques aren't problems a governance framework can intercept. Three fully built in, three partially covered, two outside scope."

# ─── Data Protection ───
generate "data" "Data Protection. Data at rest, in transit, and during AI processing — this is where trust meets implementation. ZeroPoint covers seventy percent of this domain. Encryption at rest is handled by the Credential Vault, using ChaCha20-Poly1305 — no compromises on the cryptography. Access controls are enforced through capability grants that define exactly who can read and write what. Privacy preservation is now fully addressed through structural amnesia — the relay retains no logs, no state, no index. It's subpoena-proof by design. There is nothing to compromise because there is nothing to retain. Scoped access and audit logging provide the compliance layer on top. Data loss prevention is partially covered — the Governance Gate enforces content policies, catching sensitive data before it leaves the perimeter. Training data security is the one area outside scope — it's a training-time concern that sits upstream of runtime governance. Three built in, one partial, one outside scope."

# ─── Infrastructure ───
generate "infra" "Infrastructure. Network segmentation, firewalls, endpoint protection, deployment pipelines — this is the traditional infrastructure layer. And ZeroPoint is transparent about it: this is mostly outside scope. ZeroPoint is a governance framework, not a network appliance. It doesn't replace your firewalls, your intrusion detection, or your endpoint security. What it does touch is transport — ZeroPoint now runs dual-backend transport across a WebSocket relay and Reticulum mesh, with TLS on the web path and end-to-end encryption on both. The infrastructure domain is where you layer complementary tools around ZeroPoint. It secures the agent layer. Your infrastructure stack secures everything else. One partial, five outside scope — and that's by design."

echo ""
echo "Done. Generated 8 narration files in ${OUT_DIR}/"
echo "Voice: Kusal (en_US-kusal-medium) @ 1.35x"
echo "Noise: scale=${NOISE_SCALE} w=${NOISE_W}"
