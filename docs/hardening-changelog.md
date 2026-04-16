# Security hardening changelog

**Scope:** Hardening work performed during the ARTEMIS pentest relay
cycle (relay commands 020–025), April 2026.
**Purpose:** Capture every security-relevant change so that future
auditors and pentesters have a clear baseline of what was fixed, when,
and why.

## Summary

Over six relay cycles, ARTEMIS (an isolated pentest operator) executed
automated and manual tests against the ZeroPoint codebase. Each relay
produced a command script, execution log, and verification result. The
work below was driven by those findings plus pre-existing backlog items.

Final status: **13/13 tests passing on relay 025. All security-critical
paths verified end-to-end.**

---

## Phase 6.2: Auth hardening (relay 020 baseline)

**Commit:** `78838f6`

- HMAC-SHA256 session tokens with constant-time comparison
- Per-IP failed-auth rate limiting (10/min)
- Per-endpoint rate limiting (5–30 req/min depending on operation)
- TLS-enforced cookies: `HttpOnly`, `SameSite=Strict`, `Secure`
- Session expiry (8h default)
- Canon permission enforcement at startup: refuses to run if plaintext
  secret files exist or if `~/.zeropoint` has loose permissions

## CSP compliance and asset integrity

**Commits:** `fd6f2f5`, `d0fdcfa`

- Vendored all CDN dependencies (no external script loads)
- Externalized all inline scripts from HTML
- Full Content Security Policy: `script-src 'self'`, `img-src 'self' data:`,
  `frame-ancestors 'none'`, `form-action 'self'`
- `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`
- No `unsafe-eval`, no `unsafe-inline` for scripts

## Session persistence and state accuracy

**Commits:** `2969cb2`, `c6b1cb4`

- Session token persists across `zp serve` restarts (relay 035 finding)
- Distinguished stale session from missing session in auth middleware
- Dashboard no longer lies about genesis state when session is stale
- Proper 401 with clear re-auth guidance vs 403 for genuinely missing auth

## Genesis verification

**Commit:** `578aa69`

- Signed genesis transcript verified on load
- Genesis ceremony produces cryptographically bound transcript
- Verified by relay 021: 8 unit tests + 6 live test targets all pass

## Audio narration pipeline

**Commits:** `eaceb4f`, `55e8d37`

- Narration MP3s deployed from repo to server assets directory
- Standardized audio asset pipeline with manifest and CI gating
- `audio-check.sh` validates all narration files match manifest checksums
- Relay 022 verified: 10 MP3s deployed, all unit tests pass

## Bash 3.2 compatibility

**Commit:** `76f9c1f` (part 1)

- `audio-check.sh` used `declare -A` (associative arrays), which requires
  bash 4+. macOS ships bash 3.2.
- Replaced with indexed parallel arrays (`DOMAIN_NAMES` + `DOMAIN_GENS`)
- Relay 022 flagged; fixed before relay 023

## Post-genesis onboard UX hardening

**Commits:** `76f9c1f` (part 2), `43efd94` (part 2)

Triple-layer defense against showing the genesis creation UI after
ceremony is complete:

1. **HTTP redirect:** Server redirects GET `/` to `/dashboard` when
   `genesis.json` exists.
2. **WebSocket 403:** Server rejects WS upgrade on `/api/onboard/ws`
   post-genesis with 403.
3. **Reconnect-loop detection (JS):** After 3 consecutive fast-close
   WS failures (socket never opens), client redirects to `/dashboard`
   instead of looping forever. Variables: `connectFailCount`,
   `MAX_FAST_FAILS = 3`.
4. **Genesis step guard (JS):** `genesisComplete` flag set from the WS
   state event. `goStep()` skips step 2 → step 3 when genesis is already
   done. Covers cached/stale page loads that bypass the server-side redirect.

## Mnemonic recovery pipeline

**Commits:** `1703fc4`, `43efd94` (part 1)

Full `zp recover` CLI command for mnemonic identity restoration:

- BIP-39 decode (24 words → 32-byte Ed25519 secret)
- Verify mnemonic against genesis.json public key before any side effects
- Confirm overwrite prompt comes *after* verification (relay 050 finding:
  original ordering consumed stdin before mnemonic could be read in piped
  input scenarios)
- Re-seal genesis secret to OS credential store
- Verify operator key decryption (vault key derivation sanity check)
- Error messages guide the user: wrong words, missing genesis.json,
  credential store inaccessible

Recovery was verified destructively by relay 024: ARTEMIS wiped the
keychain entry, ran `zp recover` with the real 24 words, and the system
came back to life.

## Relay verification summary

| Relay | Focus | Result | Key finding |
|-------|-------|--------|-------------|
| 020 | Baseline build + auth | PASS | Established pentest baseline |
| 021 | Genesis verify | SHIP IT | 8 unit tests, 6 live targets pass |
| 022 | Narration deploy | PASS | 10 MP3s deployed; bash 3.2 compat flagged |
| 023 | Mnemonic recovery lib | SHIP IT | 8 unit + 8 integration tests; live mnemonic match confirmed |
| 024 | `zp recover` CLI | SHIP IT | Destructive recovery verified; confirm-before-verify ordering bug caught |
| 025 | Ordering fix + onboard guard | ALL PASS | 13/13 tests; both fixes verified |

## Attack surface audit (post-hardening)

Conducted after relay 025. No security-critical gaps identified.

| Surface | Status | Controls |
|---------|--------|----------|
| HTTP endpoints | Hardened | 401 on missing/stale tokens; 429 rate limit; secure headers |
| WebSocket handlers | Hardened | Frame size limits (64KB exec, 128KB onboard); step-ordering enforcement |
| Credential storage | Hardened | OS keyring; BLAKE3 vault key; ChaCha20-Poly1305; no plaintext on disk |
| File handling | Hardened | Path traversal blocked; canonicalize enforced; `.ssh`/`.git` rejected |
| Exec/command | Hardened | 52-prefix allowlist + 16 blocked patterns; cwd confined to $HOME |
| CSP headers | Hardened | script-src 'self'; frame-ancestors 'none'; DENY X-Frame-Options |
| Auth middleware | Hardened | Constant-time comparison; rotation invalidates old tokens; per-IP rate limits |
