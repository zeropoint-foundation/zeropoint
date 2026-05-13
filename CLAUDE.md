# Memory

## Me
Ken Romero (kenrom), Founder of ThinkStream Labs. Building ZeroPoint — portable trust infrastructure for the Agentic Age.

## Infrastructure
| Resource | Details |
|----------|---------|
| **Domain** | zeropoint.global — Cloudflare Workers |
| **Domain** | thinkstreamlabs.ai — Cloudflare Workers |
| **GitHub** | zeropoint-foundation/zeropoint |

## Terms
| Term | Meaning |
|------|---------|
| ZP | ZeroPoint |
| zp-playground | Remote server running ZeroPoint server |
| Playground | zeropoint.global/playground — interactive governance demo |
| APOLLO | Ken's primary dev machine. Both dev environment and ZP runtime. |
| ARTEMIS | Portable system, also used as clean environment for installation and workflow testing |

## Machines
| Name | Role |
|------|------|
| **APOLLO** | Ken's primary machine. Source at `~/projects/zeropoint`, runtime at `~/ZeroPoint/`. Both dev and ZP runtime. |
| **ARTEMIS** | Travel system + clean install testing. Has Touch ID for biometric sovereignty testing |
| **zp-playground** | Remote ZP server |

## Hardware for Testing
| Device | Purpose |
|--------|---------|
| **Trezor** | Hardware wallet with existing Genesis keys — test Trezor sovereignty provider |
| **ARTEMIS Touch ID** | Test Touch ID sovereignty provider from clean install |

## Projects
| Name | What |
|------|------|
| **ZeroPoint** | Cryptographic governance primitives for autonomous agent systems |
| **zeropoint.global** | Public website (gitignored, use `git add -f`) |
| **thinkstreamlabs.ai** | Company website — light theme, Cloudflare Workers |

## Key Paths (APOLLO)
| Path | What |
|------|------|
| `~/projects/zeropoint` | Source code (Cargo workspace root) |
| `~/ZeroPoint/` | Runtime home — vault.json, genesis.json, session.json |
| `~/ZeroPoint/data/audit.db` | Audit chain (SQLite) |
| `~/ZeroPoint/keys/` | Signing keys |

## Preferences
- Git doesn't work from Cowork sandbox — Ken runs git locally from ~/projects/zeropoint
- zeropoint.global files are gitignored — must use `git add -f zeropoint.global/`
- Dark theme design system: --bg: #0a0a0c, accent: #7eb8da, Inter + JetBrains Mono
- **Browser**: Uses Comet browser (NOT Chrome). Claude MCP is available via Comet tabs. Do NOT use Claude in Chrome MCP tools — they don't exist here.
- **Dev workflow**: `./zp-dev.sh` (dev build), `./zp-dev.sh html` (instant HTML reload), `./zp-dev.sh release` (ship)

## Tone preferences

**Don't shape the session by time of day — this is a hard rule, restated more than once.** Treat it as non-negotiable; the time-stamped warm-closer instinct keeps slipping through and it needs to stop.

The rule is about *time framing*, not about being formal or cold. Saying hello, hi, good to hear from you, glad you're back — all fine. Friendly closers like "good arc," "pleasure was mine," "noted," "your call" — all fine. The warmth lives in the content, not in time.

Drop, do not soften:

- Time-of-day greetings or closers: "good morning," "good evening," "good afternoon," "sleep well," "have a good night," "rest up," "catch you tomorrow"
- References to "today," "tonight," "this morning," "this evening," when describing the work — say "the work," "the arc," "the next step," "this session"
- Day-shape assumptions: "before you turn in," "we're at the end of a long day," "first thing in the morning," "after the weekend"
- Asking about Ken's day or wellbeing as conversational filler

Ken's work doesn't have a "day" shape; assuming it does is patronizing and breaks the flow.

## Asset Architecture (Two-Tier)
| Tier | Location | When |
|------|----------|------|
| **Override** | `~/ZeroPoint/assets/` (or `$ZP_ASSETS_DIR`) | Hot reload (`./zp-dev.sh html`) copies source here. Persistent files (narration MP3s, images) live here always. |
| **Compiled-in** | `include_str!()` in binary | Always available. Matches last `cargo build`. Dev/release builds delete overrides so compiled-in takes effect. |

**Rules**: No relative ServeDir paths. Override dir is the single ServeDir root. `resolve_html_asset()` checks override → compiled-in. Two file categories in `zp-dev.sh`: `HTML_FILES` (have compiled-in fallback, deleted after build) and `STATIC_FILES` (CSS/JS, no fallback, always deployed to override dir).

## TTS / Voice
| Component | Details |
|-----------|---------|
| **Engine** | Piper TTS (local) |
| **Models** | Kusal (primary), Amy (secondary) — stored in `models/piper/` |
| **TTS server** | `voice-tuner-server.py` → `localhost:8473` — HTTP wrapper around Piper |
| **Speak page** | `localhost:3000/speak` — paste text, hear it via Piper |
| **CLI speak** | `./zp-speak.sh` — pipe text or reads clipboard |
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

## Canonical Architecture Record

**`docs/ARCHITECTURE-2026-04.md`** is the north star. Read it before making any structural decision. It is not a reference document — it is the operating spec. Code that contradicts it is wrong.

**The four claims** (Part I §2) are the substrate's acceptance criteria. Two are currently false (Claim 1: chain integrity, Claim 3: gate enforcement). Every phase of work should move at least one claim closer to true. If proposed work doesn't advance a claim, question whether it belongs.

**The six design principles** (Part V½) are a mandatory filter for every architectural decision:

1. **Signing is gravity** — unsigned Receipts are structurally meaningless. If it works without signing, signing is decorative.
2. **Identity is a key, not a location** — bead zero is the identity, not the port or hostname.
3. **There is no center** — trust state is derived locally from the audit chain, never from a remote authority.
4. **Every bit counts** — no redundant fields, no duplicate data paths, no wasted cognitive bandwidth.
5. **Store-and-forward is primary** — the chain survives outages. Derived state, not live state.
6. **A tool is intent, crystallized** — semantics in structure, not in comments. Constitutional rules are conservation laws.

**Companion documents**: `whitepaper-v2.md` (public thesis), `design/governed-agent-runtime.md` (GAR spec), `future-work/cognitive-accountability.md` (Layer 3 trace vision).

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

## Working principles (Karpathy-style)

These shape *how* to work in this repo, not what to know about it. Co-equal with the graphify directive below; both are behavioral rules, not encyclopedic context.

### Think before coding

For any non-trivial change:

- If intent is ambiguous, ASK before assuming. A clarifying question costs less than a wrong implementation.
- For architectural decisions, surface the trade-off explicitly before picking. The architecture doc (`docs/ARCHITECTURE-2026-05.md`) and the seam catalog (`docs/STRUCTURAL-AUDIT-2026-05.md`) exist to be consulted.
- Outline the change shape (which files, which abstractions) before editing. Easier to course-correct an outline than a half-built diff.

### Simplicity first

Prefer the smallest viable change. The substrate is large enough that adding bloat compounds. If a feature can be expressed in 20 lines instead of 200, do the 20.

The discipline-pin system, the verb-set frame, and Architecture II.0 (contracts singular, implementations plural) all point in this direction. A new abstraction must justify its existence; an existing one should not be casually rewrapped.

### Surgical changes

Touch what's needed for the requested change. Do NOT:

- Reformat unrelated code in the same file
- Rewrite imports, comments, or structure that isn't the target
- "Clean up" adjacent code as a courtesy
- Refactor as a side effect

If you notice something genuinely worth fixing nearby, surface it as a separate task, not a same-commit drive-by. The pre-push hook and discipline pins enforce some of this; the rest is on you.

### Goal-driven, not step-driven

Ken describes what "done" looks like; you choose the path. If the goal is "users can attest delegation withdrawal," that's the success criterion — the verb-set verbs, the receipt schema, the storage shape are yours to propose and confirm.

If steps are unclear, ask "what does done look like?" rather than guessing.

### When in doubt

Subagent dispatch (Sonnet) for mechanical sweeps, surveys, and verification passes. Primary context for architectural reasoning, ambiguous-intent moments, and code that informs the current decision. See `docs/MODEL-SELECTION-2026-05.md` for the per-task calibration.

## Workflow heuristics

Patterns worth replicating, captured at the moment they fire. Each entry is one heuristic plus the example that revealed it. Append new ones; don't prune.

### Name and shape artifacts for their downstream consumer, not their immediate producer.

When creating anything with a downstream consumer — config file, env var, JSON schema, API endpoint, function signature, even a hypothetical-future consumer — ask *who reads this?* before *who writes it?* and name/shape from the reader's side.

Example (2026-05-12): the Kokoro tuner saves voice favorites to a JSON file. Could have called it `tuner-favorites.json` (producer-side) or `kokoro-saved.json` (tool-side). Called it `onboarding-voice-palette.json` — what the wizard's Phase 5.5 actually reads. The wizard wiring then falls out with no translation layer, no mapping config, no "this is actually X" comment in three places. The filename IS the contract.

Anti-pattern: naming for the producer or the moment of creation. That forces either (a) a rename later, (b) a config mapping, or (c) docstring glue saying "this file means Y." All three are cognitive-bandwidth tax that consumer-side naming avoids.

When no consumer exists yet: name for the *probable* consumer. Right → free integration later. Wrong → rename costs nothing while nothing depends on it.

Connects to *every bit counts* (no translation layer) and *a tool is intent, crystallized* (the name carries the semantics structurally).

### For systems spanning trust boundaries, only production tests production.

Localhost cannot reproduce what happens at edges: cross-subdomain cookies, CDN-injected auth (Cloudflare Access JWTs, etc.), worker route ownership conflicts, per-worker secret stores, DNS resolution, the gap between local D1 and remote D1 migration state. Any system whose correctness depends on identity flowing across origins, gateways, or proxies will look correct in localhost while breaking in production.

Example (2026-05-13): the substrate-session HMAC bridge worked perfectly on localhost — wizard issued cookie, IronClaw verified it, handoff cleared. On production, six distinct frictions appeared that localhost couldn't have surfaced: CF Access intercepting at the edge, `zeropoint-global` worker still claiming the foundation routes, secrets needing per-worker mirroring, D1 migrations diverged between `--local` and `--remote`, browser cookies persisting across the dual-auth attempt, and the wizard's "already onboarded" branch becoming a dead-end. None visible until we actually deployed.

The fix is to deploy and walk through from production *early* — not as the validation pass at the end. If the system spans a trust boundary, treat localhost as a dev rig, not as a test rig. A 10-minute production walkthrough mid-build catches what hours of localhost iteration miss.

Connects to *signing is gravity* (the boundary IS the point; testing without it tests nothing) and *store-and-forward is primary* (production state is the real state).

### Demonstrate publicly with prerendered paths; interpret internally with live agents.

When demonstrating the substrate publicly — marketing exhibits, educational chain views, public-facing tours — every narration path is prerendered and every interactive branch is deterministic. No live LLM call. No live agent surface. The *voice* of an agent (Sage's character, copy patterns, phrasings) can be present through carefully authored copy bound to specific UI events. But the *running agent* stays behind authentication.

Internal surfaces — where operators are authenticated and accountable — can host live agent interpretation: ask Sage what happened, get a chain-grounded answer; let Sage suggest the next action based on operator-specific context. Live agency is a real capability, but it's an authorization-bound one.

Example (2026-05-13): the receipt chain visualization was first drafted with "Sage narrates" wording that read as live-agent-on-marketing-site. Corrected to: Sage's voice surfaces through prerendered copy bound to UI events on public surfaces; live conversational Sage stays inside the authenticated foundation surface only. The public chain demo's verification and tampering interactions are also deterministic — visitor clicks verify, math runs, result shown; no LLM decides what to display.

Why this is load-bearing:
- **Accountability surfaces must match the chain by construction.** The chain shows what actually happened; the narration must agree. A non-deterministic narrator can drift, contradict, or be prompt-injected into saying something off-message — defeating the trust thesis the demo is supposed to deliver.
- **Prerendered paths preserve cryptographic verifiability.** The chain says X; the narration says X; both agree because the narration was authored to say X when X happens. There's no place a runtime could lie.
- **Authorization bounds cost, abuse surface, and context quality.** Internal agent calls happen for known operators with rich context (their session, their receipts, their role). Public agent calls would be anonymous, infinite-scale, context-poor — strictly worse on every dimension.
- **Voice and agency are different capabilities, deployable at different tiers.** "Sage as a character" is brand and copywriting. "Sage as a running agent" is a runtime surface with operational posture. Confusing the two leads to accidentally exposing runtime where only brand was intended.

Connects to *signing is gravity* (deterministic verifiability is structural, not decorative) and *identity is a key, not a location* (the right to interact with an agent is authorization-bound, not URL-bound).

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- ALWAYS read graphify-out/GRAPH_REPORT.md before reading any source files, running grep/glob searches, or answering codebase questions. The graph is your primary map of the codebase.
- IF graphify-out/wiki/index.md EXISTS, navigate it instead of reading raw files
- For cross-module "how does X relate to Y" questions, prefer `graphify query "<question>"`, `graphify path "<A>" "<B>"`, or `graphify explain "<concept>"` over grep — these traverse the graph's EXTRACTED + INFERRED edges instead of scanning files
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
