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
| APOLLO-3 | Mac Mini at 192.168.1.170 — runs dnsmasq DNS shield with Steven Black blocklist |

## Local Network
| Component | Details |
|-----------|---------|
| **Gateway** | AT&T BGW210-700 @ 192.168.1.254 — will be set to IP Passthrough (dumb modem) |
| **Router** | ASUS RT-AX58U (v1) w/ Merlin firmware — arriving 2026-03-13, located in the Barn |
| **Topology** | Main House (BGW210) → ethernet → Barn (ASUS primary router) → Studio (AT&T extender for now) |
| **DNS** | Cloudflare 1.1.1.1 / 1.0.0.1 — set globally on ASUS once deployed |
| **APOLLO-3** | Mac Mini @ 192.168.1.170 — dnsmasq + Steven Black blocklist (to be migrated to ASUS Merlin) |
| **Block list** | MACs to block: 38:a5:c9:20:4a:a5 (Tuya), b4:61:e9:e2:16:0b (AI-Link), b4:61:e9:e2:3a:8c (AI-Link) |
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
