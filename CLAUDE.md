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
| **Override** | `~/.zeropoint/assets/` (or `$ZP_ASSETS_DIR`) | Hot reload (`./zp-dev.sh html`) copies source here. Persistent files (narration MP3s, images) live here always. |
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
| **Narration output** | `~/.zeropoint/assets/narration/onboard/` — permanent, never compiled in |
| **Narration source** | `generate-narration-onboard.py` → `generate-audio-onboard.sh` |

## TODO (Deferred)
| Item | Context |
|------|---------|
| **Re-enable ZP Guard in .zshrc** | Hardened 3-layer hook ready in `docs/GUARD-SAFE-RENABLE.md`. Validate `zp guard -s "ls"` < 50ms, then paste hook into `~/.zshrc`. Related: `crates/zp-cli/src/guard.rs` |
