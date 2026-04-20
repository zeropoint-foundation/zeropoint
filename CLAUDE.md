# Memory

## Me
Ken Romero (kenrom), Founder of ThinkStream Labs. Building ZeroPoint — portable trust infrastructure for the Agentic Age.

## Infrastructure
| Resource | Details |
|----------|---------|
| **Hetzner** | `ssh -i ~/.ssh/hetzner_zp root@89.167.86.60` — "zp-playground" CX23, Helsinki |
| **Domain** | zeropoint.global — Cloudflare Workers |
| **Domain** | thinkstreamlabs.ai — Cloudflare Workers |
| **GitHub** | zeropoint-foundation/zeropoint |
| **Substack** | @kenrom369 |

## Terms
| Term | Meaning |
|------|---------|
| ZP | ZeroPoint |
| zp-playground | Hetzner server running ZeroPoint server |
| Playground | zeropoint.global/playground — interactive governance demo |
| Barn | Elevated structure between main house and studio — central hub for network router |
| APOLLO-3 | Mac Mini at 192.168.1.170 — retired as DNS shield (Sentinel handles DNS now). Available for repurposing as ZP Core server, ledger node, or monitoring collector |
| ARTEMIS | M4 MacBook Pro — traveling system, also used as clean environment for installation and workflow testing |

## Machines
| Name | Hardware | Role |
|------|----------|------|
| **APOLLO-3** | Mac Mini @ 192.168.1.170 | Available for repurposing (ZP Core, ledger node, monitoring) |
| **ARTEMIS** | M4 MacBook Pro (portable) | Travel system + clean install testing. Has Touch ID for biometric sovereignty testing |
| **zp-playground** | Hetzner CX23, Helsinki | Remote ZP server |

## Hardware for Testing
| Device | Purpose |
|--------|---------|
| **Trezor** | Hardware wallet with existing Genesis keys — test Trezor sovereignty provider |
| **ARTEMIS Touch ID** | Test Touch ID sovereignty provider from clean install |

## Local Network
| Component | Details |
|-----------|---------|
| **Gateway** | AT&T BGW210-700 @ 192.168.1.254 — will be set to IP Passthrough (dumb modem) |
| **Router** | ASUS RT-AX58U (v1) w/ Merlin firmware — arriving 2026-03-13, located in the Barn |
| **Topology** | Main House (BGW210) → ethernet → Barn (ASUS primary router) → Studio (AT&T extender for now) |
| **DNS** | Cloudflare 1.1.1.1 / 1.0.0.1 — set globally on ASUS. Sentinel handles DNS filtering + Steven Black blocklist |
| **Sentinel** | ZP Network Sentinel on ASUS Merlin — DNS filtering, device monitoring, anomaly detection, mesh peer via AgentAnnounce |
| **APOLLO-3** | Mac Mini @ 192.168.1.170 — retired from DNS duty. Available for repurposing as ZP Core server, ledger node, or monitoring collector |
| **Block list** | MACs to block (managed by Sentinel): 38:a5:c9:20:4a:a5 (Tuya), b4:61:e9:e2:16:0b (AI-Link), b4:61:e9:e2:3a:8c (AI-Link) |
| **Monitor** | dns-monitor.py — ZP-themed traffic dashboard, not yet deployed |

## Projects
| Name | What |
|------|------|
| **ZeroPoint** | Cryptographic governance primitives for autonomous agent systems |
| **zeropoint.global** | Public website (gitignored, use `git add -f`) |
| **thinkstreamlabs.ai** | Company website — light theme, Cloudflare Workers |

## Preferences
- Git doesn't work from Cowork sandbox — Ken runs git locally from ~/projects/zeropoint
- zeropoint.global files are gitignored — must use `git add -f zeropoint.global/`
- Dark theme design system: --bg: #0a0a0c, accent: #7eb8da, Inter + JetBrains Mono
- **Browser**: Uses Comet browser (NOT Chrome). Claude MCP is available via Comet tabs. Do NOT use Claude in Chrome MCP tools — they don't exist here.
- **Dev workflow**: `./zp-dev.sh` (dev build), `./zp-dev.sh html` (instant HTML reload), `./zp-dev.sh release` (ship)

## Asset Architecture (Two-Tier)
| Tier | Location | When |
|------|----------|------|
| **Override** | `~/ZeroPoint/assets/` (or `$ZP_ASSETS_DIR`) | Hot reload (`./zp-dev.sh html`) copies source here. Persistent files (narration MP3s, images) live here always. |
| **Compiled-in** | `include_str!()` in binary | Always available. Matches last `cargo build`. Dev/release builds delete overrides so compiled-in takes effect. |

**Rules**: No relative ServeDir paths. Override dir is the single ServeDir root. `resolve_html_asset()` checks override → compiled-in. Two file categories in `zp-dev.sh`: `HTML_FILES` (have compiled-in fallback, deleted after build) and `STATIC_FILES` (CSS/JS, no fallback, always deployed to override dir).

## TTS / Voice
| Component | Details |
|-----------|---------|
| **Piper binary** | `/Users/kenrom/anaconda3/bin/piper` |
| **Models** | `~/projects/zeropoint/models/piper/` — Kusal (primary), Amy (secondary) |
| **TTS server** | `python3 voice-tuner-server.py` → `localhost:8473` — HTTP wrapper around Piper |
| **Voice Tuner** | `voice-tuner.html` — standalone page for voice param tuning |
| **Speak page** | `localhost:3000/speak` — paste text, hear it via Piper. Auto-reads clipboard on focus. |
| **CLI speak** | `./zp-speak.sh` — pipe text or reads clipboard, plays via `afplay` |
| **Narration voices** | Kusal (even steps + recovery), Amy (odd steps). Params: length_scale 0.7692, noise_scale 0.360, noise_w 0.930, sentence_silence 0.30 |
| **Narration output** | `~/ZeroPoint/assets/narration/onboard/` — permanent, never compiled in |
| **Narration source** | `generate-narration-onboard.py` → `generate-audio-onboard.sh` |

## Sovereignty Provider System
The Genesis secret is always a 32-byte Ed25519 seed generated by ZeroPoint. The sovereignty provider controls HOW it's stored and WHO can unlock it.

| Module | Path | Status |
|--------|------|--------|
| **Trait + enum** | `crates/zp-keys/src/sovereignty/mod.rs` | Complete |
| **Touch ID** | `sovereignty/touchid.rs` | v0.1 (application-layer via bioutil) |
| **Fingerprint** | `sovereignty/fingerprint.rs` | v0.1 (fprintd-verify) |
| **Face Enroll** | `sovereignty/face.rs` | Requires `face-enroll` feature + OpenCV |
| **Windows Hello** | `sovereignty/windows_hello.rs` | v0.1 (PowerShell + keyring). v0.2 = native WinRT via `windows` crate |
| **YubiKey** | `sovereignty/hardware/yubikey.rs` | Detection only; FIDO2 impl = v0.3 |
| **Ledger** | `sovereignty/hardware/ledger.rs` | Detection only; impl = v0.3 |
| **Trezor** | `sovereignty/hardware/trezor.rs` | Detection only; impl = v0.3 |
| **OnlyKey** | `sovereignty/hardware/onlykey.rs` | Detection only; impl = v0.3 |
| **Login Password** | `sovereignty/login_password.rs` | Complete |
| **File** | `sovereignty/file_based.rs` | Complete |
| **Detection shim** | `sovereignty/detection.rs` | Backward compat for old `detect_biometric()` |
| **Legacy shim** | `biometric.rs` | Re-exports from sovereignty/, backward compat |

**Blast radius for sovereignty changes**: `biometric.rs` (shim), `lib.rs` (re-exports), `onboard/genesis.rs` (ceremony), `onboard/detect.rs` (provider scan), `onboard/state.rs` (step machine), `onboard.html` (sovereignty cards), `onboard.js` (updatePlatformUI + selectSovereignty + showGenesisComplete + summary labels), `narration/onboard/scripts.md` (narration mentions biometrics), `dashboard.html` (sovereignty badge display), `security.rs` (posture check).

**Feature flags** (in `zp-keys/Cargo.toml`): `os-keychain`, `face-enroll`, `hw-yubikey`, `hw-ledger`, `hw-trezor`, `hw-onlykey`.

## TODO (Deferred)
| Item | Context |
|------|---------|
| **ZP Guard allowlist tuning** | Guard is firing on routine dev commands (`python3`, `bash`) in the project directory. Tune allowlist so common dev workflows don't trigger blocks. Validate `zp guard -s "ls"` < 50ms. Related: `crates/zp-cli/src/guard.rs`, `docs/GUARD-SAFE-RENABLE.md` |
| **Trezor passphrase support** | `derive_wrapping_key()` auto-responds with empty string to `PassphraseRequest`. Add passphrase prompt path for users with passphrase-protected wallets. Consider TrezorConnect web bridge for richer device interaction |
| **Touch ID v0.2 (Secure Enclave)** | Replace `bioutil -w` application-layer check with `security-framework` crate using `kSecAccessControlBiometryCurrentSet` for OS-level enforcement |
| **Face enrollment v0.2** | Replace BLAKE3 pixel hashing with proper face embeddings (FaceNet/ArcFace via ONNX) for lighting-invariant matching |
| **Windows Hello v0.2 (native WinRT)** | Replace PowerShell shims with `windows` crate WinRT bindings for `UserConsentVerifier` and `KeyCredentialManager`. Direct TPM-backed key creation with biometric access policy |
| **YubiKey v0.3** | FIDO2 hmac-secret extension for wrapping key derivation. Needs `ctap-hid-fido2` + `hidapi` crates. Resident credential creation, credential ID persistence, feature-aware `Ready` status like Trezor |
| **Ledger v0.3** | BIP-32 derivation via APDU commands. Needs `ledger-transport-hid` + `ledger-apdu` crates. Key export API unclear — may need HMAC-based derivation instead of raw key |
| **OnlyKey v0.3** | HMAC-SHA1 challenge-response via configured slot. Simplest protocol after Trezor CipherKeyValue — good next candidate |

## Architecture Direction: Multi-Signing / Quorum Sovereignty

The sovereignty provider system should be designed from the ground up for multi-device quorum support (e.g., 2-of-3 Trezors, or 1 Trezor + 1 YubiKey). Architectural implications:

| Area | Current (1:1) | Target (M-of-N) |
|------|---------------|------------------|
| **Enrollment** | One device, one `{mode}_enrollment.json` | Multiple enrolled devices, each with own enrollment + share |
| **Wrapping** | Single wrapping key encrypts Genesis | Shamir Secret Sharing or threshold encryption across N devices |
| **Ceremony** | One device confirms | M-of-N devices must confirm (sequential or parallel) |
| **Recovery** | 24-word BIP-39 mnemonic | Mnemonic covers the combined secret; individual device loss tolerated if M threshold met |
| **Storage** | `{mode}_genesis.encrypted` | Per-device share files + quorum metadata |
| **Provider trait** | `save_secret(&[u8; 32])` takes whole secret | Needs `save_share(share: &Share, quorum: &QuorumConfig)` |

**Near-term**: Don't break the 1:1 path — it's correct for personal sovereignty. But keep the door open:
- `EnrollmentMetadata.provider_data` should anticipate quorum fields (share_index, threshold, quorum_id)
- File naming should tolerate multiple enrollments per mode (`trezor_0_enrollment.json`, `trezor_1_enrollment.json`)
- The `SovereigntyProvider` trait may need a `QuorumProvider` extension trait rather than modifying the base trait

**Key decision**: Shamir Secret Sharing (split Genesis into shares) vs. threshold signatures (each device signs independently, combine). SSS is simpler for wrapping key derivation; threshold sigs are more powerful for agent certificate issuance. Both may be needed at different layers.

## Intellectual Context & Adjacent Thinkers

| Source | Key Thesis | ZP Connection |
|--------|-----------|---------------|
| **Autoregressive theory** (Ken's talk notes) | Autoregression is a unifying computational principle (language, cognition, physics). Trust-as-trajectory is the accessible framing. | Theoretical bedrock of ZP. Architecture independently converged on autoregressive patterns; theory provides vocabulary for why it works. Whitepaper v2.1 grounds all four tenets in this. |
| **LARQL** (Bytez, 2024) | Transformer FFN layers can be decomposed as a graph database (entities=nodes, features=edges, relations=labels). Vindex format enables KNN graph-walk inference and surgical knowledge editing (INSERT→COMPILE). | Shares ZP's "legibility as prerequisite for accountability" aesthetic. Composes with ZP: agent-native knowledge with per-fact provenance chains. Future work: cognitive accountability layer. See `docs/future-work/cognitive-accountability.md`, `docs/design/larql-integration.md`, `docs/related-work-larql.md`. |
| **MEDS** (Memory-Enhanced Dynamic Reward Shaping, 2025) | Layer-wise logit fingerprints reveal recurring error patterns in LLM reasoning. HDBSCAN clustering identifies "stable error basins" — dense regions of activation space where the same faulty logic recurs despite varied wording. Deep layers (~last 14) encode logic, not grammar. | Complementary to LARQL: LARQL decomposes what the model *knows*, MEDS characterizes how it *reasons*. Together they provide both inputs for the trace layer (Layer 3 of the three-layer accountability stack). Error basins = drift detection signal. Confabulation gap = divergence between stated reasoning and actual computation. See `docs/design/larql-integration.md`, `docs/related-work-larql.md`. |
| **Nate Jones** (agentic infrastructure) | AI is already fast; the bottleneck is human-speed software. Rebuild tools as agent-native primitives. Humans move "above the loop" into coordination/judgment roles. Bifurcated web: agentic layer at superhuman speed, human layer at our pace. | ZP receipts ARE agent-native trust primitives (no dashboards, no login screens). Delegation narrowing enables the bifurcation: agents execute fast within scope, humans audit the trajectory at their own speed. Sovereignty holder = Jones's "adult in the room" with cryptographically enforced constraints. |

## HW Wallet Architecture Notes

**Shared infrastructure** (`sovereignty/hardware/mod.rs`): Provides `encrypt_secret`/`decrypt_secret` (ChaCha20-Poly1305 with deterministic BLAKE3 nonce), `EnrollmentMetadata`, and file I/O for `{mode}_enrollment.json` + `{mode}_genesis.encrypted`. Each device only needs to produce a 32-byte wrapping key.

**Feature-aware readiness**: Only Trezor has `cfg!(feature = "hw-trezor")` → `Ready` in `implementation_status()`. When YubiKey/Ledger/OnlyKey get implemented, each needs the same pattern. Consider a macro to reduce copy-paste.

**Enrollment `provider_data`**: Currently untyped `serde_json::Value`. Works for v0.1 but should evolve to a `ProviderData` enum with per-device variants for compile-time safety when multiple devices are in play.
