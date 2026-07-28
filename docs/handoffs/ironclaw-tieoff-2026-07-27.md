# IronClaw tie-off — what's done, what's yours

**Date:** 2026-07-27. Repo-side work is applied on APOLLO. Everything in §2–§4 needs
network or macOS access this session doesn't have.

---

## 1. Done in the repo

**Launch artifacts moved to `_to_delete/ironclaw-tieoff-2026-07-27/`** (device_bash
cannot `rm`; this is the move-aside pattern — delete that folder yourself when satisfied):

- `scripts/start-ironclaw.sh`
- `scripts/apply-ironclaw-plist.sh`
- `scripts/setup-foundation-login-item.sh`
- `scripts/IronClaw Foundation Agent.app/`
- `tools/ironclaw/` (`.zp-configure.toml`)

**Env injection removed entirely**, per your ruling:

| File | Change |
|---|---|
| `crates/zp-server/src/lib.rs` ~5514 | dropped `.env("IRONCLAW_ZP_ENABLED", "true")`; `.env("ZP_GOVERNED", "1")` now terminates the chain |
| `crates/zp-server/src/lib.rs` ~5711 | removed `"IRONCLAW_ZP_ENABLED"` from `ZP_OWNED_VARS` and from the comment above it |
| `crates/zp-cli/src/main.rs` ~2636 | dropped the `genesis_record_path()` → `child.env("IRONCLAW_ZP_GENESIS_PATH", …)` block and its comment |

**Not built.** No `cargo check` was run — the mount is macOS files reached from a Linux
VM, and building there would be wrong. Run `./zp-dev.sh` before trusting it. The edits are
three deletions from string literals and one statement-terminator change; the expected
failure mode is a warning, not an error.

**One dangling consumer:** `tools/gate-ping/src/main.rs:24` still reads
`IRONCLAW_ZP_GENESIS_PATH`. Nothing sets it now, so that diagnostic will fail to find the
var. You kept `gate-ping` deliberately — flagging it so the failure isn't a surprise.

**Left alone on purpose:** the `ZP_GOVERNED` comment above the edit still explains itself
in terms of "IronClaw's own singleton enforcement." Stale, but it documents `ZP_GOVERNED`'s
intent rather than IronClaw's existence, and rewriting it was outside what you asked for.

---

## 2. On GitHub — the source of the mail

The four failing workflows ("Docker Image", "Live Canary", "Nightly Deep CI", "Nightly E2E")
are **not** in the `zeropoint` repo. `.github/workflows/` there holds only `ci.yml`,
`pages.yml`, `release.yml`, `static.yml`, all on `ubuntu-latest`, none referencing a
self-hosted runner. They live in `zeropoint-foundation/ironclaw` itself.

Cleanest stop, in descending order of finality:

```bash
# Option A — archive the repo. Disables all workflows, stops all mail, keeps history.
gh repo archive zeropoint-foundation/ironclaw

# Option B — disable the four workflows individually, keep the repo writable.
gh workflow list --repo zeropoint-foundation/ironclaw
gh workflow disable "Docker Image"    --repo zeropoint-foundation/ironclaw
gh workflow disable "Live Canary"     --repo zeropoint-foundation/ironclaw
gh workflow disable "Nightly Deep CI" --repo zeropoint-foundation/ironclaw
gh workflow disable "Nightly E2E"     --repo zeropoint-foundation/ironclaw

# Either way — stop watching so notifications end even if something re-enables.
gh api -X PUT repos/zeropoint-foundation/ironclaw/subscription \
  -f subscribed=false -f ignored=true
```

Archiving is the better fit for something removed from the stack: GitHub's "will be
disabled soon" warnings are the inactivity timer, and archiving ends that conversation
rather than deferring it 60 days.

**The self-hosted runner.** The label `zp-daily-driver` appears nowhere in the zeropoint
repo as a runner label — every occurrence is a *git branch name*, so the runner was almost
certainly registered from the ironclaw repo and named after the branch. If a runner service
is still installed on APOLLO it will keep polling GitHub after the workflows stop. Check and
deregister:

```bash
ls ~/actions-runner ~/projects/ironclaw/actions-runner 2>/dev/null
# if found:
cd <runner-dir> && sudo ./svc.sh stop && sudo ./svc.sh uninstall && ./config.sh remove
# and confirm it's gone from the repo's runner list:
gh api repos/zeropoint-foundation/ironclaw/actions/runners
```

---

## 3. On Cloudflare

**The Worker needs no change.** `zeropointfoundation.org/wrangler.toml` — worker
`zeropoint-foundation`, routes `zeropointfoundation.org/*` and `www.…/*`, bindings
`ASSETS`, D1 `zpmail`, R2 `zp-storage` — contains no route, service binding, D1 name, KV
key or var referencing IronClaw. Nothing there to unwire.

**The tunnel is the real Cloudflare-side artifact.** `app.zeropointfoundation.org` was
never a Worker route — it was served through the `cloudflared` tunnel `foundation-apollo`,
installed by `scripts/apply-cloudflared-plist.sh` as LaunchAgent `homebrew.mxcl.cloudflared`,
with ingress rules in `~/.cloudflared/config.yml` on APOLLO (not in the repo, so I couldn't
read them).

```bash
cloudflared tunnel list
cloudflared tunnel info foundation-apollo
# inspect the ingress before removing anything:
cat ~/.cloudflared/config.yml
```

Then either drop the `app.` ingress rule and leave the tunnel for other hostnames, or tear
the tunnel down entirely (`cloudflared tunnel delete foundation-apollo`) plus the
`app.zeropointfoundation.org` DNS record in the dashboard. A tunnel pointing at a dead
origin is a public hostname that fails open-ended rather than 404s cleanly — worth closing.

**Orphaned by intent, not broken.** `zeropointfoundation.org/src/auth/session.js` and
`worker.js`'s `POST /api/auth/session` exist to mint a `zp_session` cookie scoped to
`.zeropointfoundation.org` so IronClaw's gateway could read it without a second auth
challenge — with the `workspace_role` claim carrying IronClaw's access level. Nothing errors
with IronClaw gone, but the session-issuance path, the `SESSION_SIGNING_KEY` secret and the
`workspace_role` column now have no consumer. Decommission or repurpose as a separate call.

---

## 4. On APOLLO

Two independent launch paths converged on the same binary, so both need unloading:

```bash
launchctl list | grep -i ironclaw
launchctl bootout gui/$(id -u)/org.zeropoint.ironclaw 2>/dev/null || \
  launchctl unload ~/Library/LaunchAgents/org.zeropoint.ironclaw.plist
rm -f ~/Library/LaunchAgents/org.zeropoint.ironclaw.plist

# Login Item — bundle org.zeropoint.ironclaw-foundation
rm -rf ~/Applications/"IronClaw Foundation Agent.app"
# then remove it under System Settings → General → Login Items

# leftovers
rm -rf ~/.ironclaw ~/Library/Logs/ZeroPoint/ironclaw.log
```

`KeepAlive.SuccessfulExit=false` on the LaunchAgent means it restarts on crash — unload
before deleting anything it points at, or it will thrash.

---

## 5. Order

1. **GitHub first** — archive or disable. Stops the mail immediately; everything else is cleanup.
2. **APOLLO** — unload the LaunchAgent and Login Item, then the runner if one exists.
3. **Cloudflare** — read `~/.cloudflared/config.yml`, then decide the tunnel's fate.
4. **Repo** — build with `./zp-dev.sh`, confirm a governed tool still launches, then delete
   `_to_delete/ironclaw-tieoff-2026-07-27/`.
5. **Foundation auth** — separate decision, no urgency.
