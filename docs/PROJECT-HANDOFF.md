# ZeroPoint Session Handoff Brief

## Who is Ken

Ken is the executive director and genesis holder of the ZeroPoint Open Foundation, a Wyoming nonprofit building a trust substrate for autonomous systems. He works fast, thinks architecturally, and will correct you sharply if you make assumptions instead of reading the codebase. Respect the architecture — it's deliberate.

## What is ZeroPoint

ZeroPoint is a governed agent runtime — a cryptographic trust substrate where every action by every agent is authenticated, authorized via capabilities, and recorded as a signed receipt in an append-only audit chain. State is never stored; it's derived from the receipt chain. The codebase spans:

- **Rust workspace** (`/zeropoint/crates/`) — the core runtime: `zp-receipt`, `zp-policy`, `zp-engine`, `zp-server`, `zp-keys`, `zp-cli`, etc.
- **Cloudflare Worker** (`/zeropoint/zeropoint.global/`) — sovereign workspace: email, docs, media, governed REST API on D1/R2
- **Frontend** (`/zeropoint/webui-next/`) — tile-based Bridge UI (React/Vite)
- **Fleet nodes** — APOLLO (primary, macOS arm64), Sentinel, Merlin
- **Tools** (`/zeropoint/tools/`) — Ember, Sentinel, audio, etc.

### Key architectural concepts

- **Governance gate**: verify identity → check capability → emit receipt. Every API call.
- **Capability model**: `mail:read:ken`, `docs:write:*`, `workspace:admin` (root). Wildcards supported.
- **Receipt chain**: append-only, hash-linked, Ed25519-signed. Chain = truth.
- **Canonicalization**: tools get a bead-zero receipt on first contact. State derived from chain.
- **Vault**: ChaCha20-Poly1305 encrypted credential store, genesis secret in OS keychain.
- **Tool manifests**: `.zp-configure.toml` declares capabilities, provider preferences, env var mappings. Configure engine resolves against vault + provider catalog.
- **Provider catalog**: `crates/zp-server/assets/providers-default.toml` — Anthropic, OpenAI, etc. with capability tags.

### The `zp` CLI (macOS arm64 binary, runs on APOLLO only)

```bash
zp configure tool --path ./tools/foo --name foo
zp preflight
zp verify        # chain integrity
zp doctor        # system health
zp scan          # F3 content scanner
zp adapt         # refresh bead-zero
zp status        # wire/bead positions
```

## Immediate deployment blocker

The `.assetsignore` fix needs `npx wrangler deploy` from the `zeropoint.global/` directory **on APOLLO**. Without this deploy:
- `.wrangler/` local D1 dev state files are being served as public static assets
- The email client UI (#325) isn't live

The `.assetsignore` file already has the fix (`.wrangler/` is listed). Just needs the deploy command run.

## Open work items

### Active / in progress

| # | Item | Status | Notes |
|---|------|--------|-------|
| 221 | GitHub Sponsors for zeropoint-foundation | in_progress | Revenue infrastructure |
| 249 | Settlement layer architecture | in_progress | Anchoring + financial settlement lifecycle |
| 294 | Staff onboarding | in_progress | Accounts, access, documents for directors |

### Ready to pick up

| # | Item | Notes |
|---|------|-------|
| 325 | Deploy email client UI | Blocked on wrangler deploy (see above) |
| 223 | ZeroPoint Open Foundation consulting inquiry path | Revenue |
| 225 | Revenue infrastructure verification | End-to-end check |
| 304 | DocuSign envelope for live signing | Foundation documents |
| 295 | Hetzner → Ashburn migration | Move server to US East |

## Board of Directors (operators in D1)

| ID | Name | Role | Capabilities |
|----|------|------|-------------|
| ken | Ken | executive_director | `workspace:admin` (root) |
| katie | Katie | treasurer | mail:read:*, mail:send/manage:katie, docs, tasks, receipts |
| carlie | Carlie | secretary | mail:read:*, mail:send/manage:carlie, docs, tasks, receipts |
| louise | Louise | director | mail:read/manage/send:louise, mail:read:info/board, docs, tasks, receipts |
| lorraine | Lorraine | director | mail:read/manage/send:lorraine, mail:read:info/board, docs, tasks, receipts |

## What was just cleaned up

- **Zift** (EnforceAuth authorization scanner) — evaluated, found useless against our bespoke architecture. Static scan found zero patterns. Deep mode would just restate what we already know. Binary and manifest deleted. Don't bring it back.
- **Bad HTTP proxy attempt** — I initially tried to bolt an LLM proxy onto the Cloudflare worker for Zift. Ken correctly called this out as wrong. The proper tool integration path is: `.zp-configure.toml` manifest → `zp configure` against vault → preflight → canonicalization into receipt chain. All reverted, worker.js/capabilities.js/wrangler.toml are clean.

## Important lessons for the next agent

1. **Read the codebase before building.** ZeroPoint has specific patterns for everything. Don't invent new ones.
2. **Tools integrate through the Rust runtime**, not the Cloudflare worker. Manifest → vault → configure engine → receipts.
3. **The `zp` binary only runs on APOLLO** (Mach-O arm64). Don't try to execute it in Cowork's sandbox.
4. **State is derived from the receipt chain.** Never store state separately.
5. **Ken says "push"** = keep building, don't ask what to do next, pick up the most impactful open item.
