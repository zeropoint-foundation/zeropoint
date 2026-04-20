# ARTEMIS Relay Protocol v2

Two agents (APOLLO + ARTEMIS), one shared filesystem. No human telephone.

**This file is the single source of truth.** Both agents MUST read this
file before every interaction. If something contradicts this file, this
file wins.

---

## 1. Directory Layout

```
zp-artemis-relay/
├── PROTOCOL.md              ← THIS FILE — read it every time
├── zp-commits.bundle        ← CANONICAL bundle (always use this one)
├── zp-artemis.bundle        ← DEPRECATED alias (copy of zp-commits.bundle)
├── manifest.json            ← HEAD state metadata
├── dispatch.log             ← Append-only commit log
├── messages/                ← Async message queue
│   └── {timestamp}-{from}-{seq}.md
├── commands/                ← Executable test/build scripts
│   └── {number}-{name}.sh
└── results/                 ← Structured output (JSON preferred)
    └── {number}-{name}.json
```

## 2. Bundle Path (CRITICAL)

The **canonical** bundle path is:

    zp-commits.bundle

APOLLO regenerates this bundle after every commit that ARTEMIS needs.
Scripts MUST prefer `zp-commits.bundle`. Fall back to `zp-artemis.bundle`
only if `zp-commits.bundle` does not exist.

**APOLLO**: After committing code changes, ALWAYS run:
```bash
git bundle create zp-artemis-relay/zp-commits.bundle main
cp zp-artemis-relay/zp-commits.bundle zp-artemis-relay/zp-artemis.bundle
```

**ARTEMIS**: To sync:
```bash
git fetch /path/to/relay/zp-commits.bundle main:artemis-incoming
git checkout main && git reset --hard artemis-incoming
git branch -D artemis-incoming
```

## 3. Message Queue

### File naming

    {ISO8601-timestamp}-{from}-{sequence}.md

Examples:
```
20260420T1800Z-apollo-006.md
20260420T0940Z-artemis-004.md
```

### Message format

```markdown
from: apollo | artemis
to: artemis | apollo
type: request | response | status | ack
ref: (filename of message this responds to)
---

Body text. Be direct. Reference file paths and commits, not inline code.
```

### Rules

- Read ALL unread messages before writing new ones.
- Every response MUST include a `ref:` to the message it answers.
- ARTEMIS: always write results back to `messages/` (not just stdout).
- APOLLO: always check for new ARTEMIS messages before prompting the user.

## 4. Test Scripts

### Location

    commands/{number}-{name}.sh

### Output

Structured JSON to `results/{number}-{name}.json` AND human-readable
summary to stdout.

### macOS Isolation (CRITICAL)

ARTEMIS runs on macOS. The real `~/.zeropoint/` directory contains
Keychain-backed credentials that trigger blocking password dialogs in
headless/automated contexts. **Every phase that executes ZeroPoint
binaries MUST override HOME:**

```bash
ISOLATED_HOME=$(mktemp -d)

# For cargo/rustup commands: resolve the real cargo binary first,
# then override HOME. The rustup shim won't work with a fake HOME.
REAL_CARGO="$(rustup which cargo)"
HOME="$ISOLATED_HOME" "$REAL_CARGO" test --workspace

# For server/CLI binaries (already compiled): just override HOME
export HOME="$ISOLATED_HOME"
"$server_bin" &
```

**CRITICAL**: `cargo` and `rustc` are rustup shims. The shim reads HOME
to find `~/.rustup/` before it checks RUSTUP_HOME. Use `rustup which
cargo` to resolve the real binary path and call it directly — this
bypasses the shim entirely.

Clean up after:
```bash
rm -rf "$ISOLATED_HOME"
```

This applies to:
- `cargo test` (test binaries may exercise credential store paths)
- Server boot (identity resolution hits Keychain at Path 1a)
- CLI smoke tests (if they exercise configure/init flows)

**SECRETS_MASTER_KEY** provides a vault key fallback so the background
resolver doesn't attempt Keychain access:
```bash
export SECRETS_MASTER_KEY="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
```

### Server Smoke Tests

The server persists a session token to `$HOME/.zeropoint/session.json`.
After the server boots and the health endpoint responds, read the token:

```bash
TOKEN=$(python3 -c "import json; print(json.load(open('$ISOLATED_HOME/.zeropoint/session.json'))['token'])")
```

Pass it on every authenticated endpoint:
```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:$PORT/api/v1/...
```

Unauthenticated routes (no token needed): `/api/v1/health`, `/healthz`,
`/readyz`, `/onboard`, `/dashboard`, `/assets/*`.

### grep Portability

macOS ships BSD grep. **Never use `grep -P`** (Perl regex). Use:
```bash
grep -oE '[0-9]+ passed'    # YES
grep -oP '\d+ passed'        # NO — fails on macOS
```

## 5. Endpoint Reference

These routes exist in the Axum router (zp-server/src/lib.rs) as of
commit 80d0b91. Use these for smoke tests — not aspirational paths:

**Unauthenticated:**
- `GET /api/v1/health`
- `GET /dashboard`

**Authenticated (require Bearer token):**
- `GET /api/v1/identity`
- `GET /api/v1/tools`
- `GET /api/v1/audit/entries`
- `GET /api/v1/audit/chain-head`
- `GET /api/v1/audit/verify`
- `GET /api/v1/events/stream` (SSE)
- `GET /api/v1/cognition/observations`
- `GET /api/v1/cognition/reviews`
- `GET /api/v1/cognition/status`
- `GET /api/v1/fleet/nodes`
- `GET /api/v1/fleet/summary`
- `GET /api/v1/security/posture`
- `GET /api/v1/security/topology`
- `POST /api/v1/security/compromise`
- `POST /api/v1/security/reconstitute`
- `GET /api/v1/policy/rules`
- `GET /api/v1/policy/wasm`
- `GET /api/v1/channels/status`
- `GET /api/v1/stats`
- `GET /api/v1/genesis`

**Routes that DO NOT exist** (common mistakes):
- ~~/api/v1/status~~ → use `/api/v1/health`
- ~~/api/v1/events~~ → use `/api/v1/events/stream`
- ~~/api/v1/cognition/memories~~ → use `/api/v1/cognition/observations`
- ~~/api/v1/cognition/review/pending~~ → use `/api/v1/cognition/reviews`
- ~~/api/v1/compromise/blast-radius~~ → use `/api/v1/security/blast-radius/:key`
- ~~/api/v1/reconstitute~~ → use `/api/v1/security/reconstitute`

## 6. Checklist — Before Dispatching to ARTEMIS

APOLLO must verify before telling ARTEMIS to run anything:

- [ ] Bundle regenerated at correct path (`zp-commits.bundle`)
- [ ] Bundle verified (`git bundle verify` shows expected HEAD)
- [ ] Both bundle paths synced (zp-commits.bundle = zp-artemis.bundle)
- [ ] Script uses HOME isolation for ALL phases that run ZP binaries
- [ ] Script uses `grep -E` not `grep -P`
- [ ] Smoke test endpoints match actual router (see §5)
- [ ] Message written to `messages/` with clear run instructions
- [ ] Message asks ARTEMIS to write results back to `messages/`

## 7. Rules

- No secrets in messages. Ever.
- Keep messages short. Reference file paths and commits, not inline code.
- If something is broken, say so directly. Don't wait to be asked.
- ARTEMIS's environment is disposable — destructive testing is fine.
- Both sides: if you're unsure about a path or convention, re-read this file.
