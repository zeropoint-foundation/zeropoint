# Design — ZP_SESSION_TOKEN Issuance & Injection for `zp configure exec`

*2026-05-14. Path B step 3 of
`docs/handoffs/substrate-readiness-checkpoint-2026-05.md`.
Investigation for `docs/handoffs/zp-session-token-issuance-2026-05.md`.
Do not ship code until this design is reviewed.*

---

## Bottom line up front

The token already exists and is already on disk. `zp-server` writes it
to `~/ZeroPoint/session.json` on startup. `zp configure exec` reads the
vault but never reads that file. The fix is four lines in the exec
handler. No new Keychain item, no new Touch ID prompt, no new token
format, no new credential-store entry — all singular-root constraints
satisfied.

---

## 1. What is ZP_SESSION_TOKEN cryptographically?

It is a 64-character hex string (32 bytes) produced by:

```
hmac_key  = SHA-256(signing_key_bytes || "zp-session-v1")
token     = hex(SHA-256(hmac_key || nonce[16] || timestamp_le[8]))
```

`crates/zp-server/src/auth.rs:8` documents this as
`hex(HMAC-SHA256(key_material, nonce || timestamp))` — the SHA-256
construction is effectively an HMAC with a derived key. The token is
deterministic given `signing_key_bytes`, but each mint uses a fresh
`rand::random()` nonce, so no two invocations produce the same value.
It has no internal expiry field; TTL is enforced purely server-side via
`created_at` recorded alongside it.

**It is not a JWT.** There is no signed payload, no claim set, no
algorithm field. It is an opaque bearer token whose value is
computationally bound to the server's identity key.

---

## 2. Who issues it (current state)?

`zp-server` issues the token at startup inside `SessionAuth::new()`
(`auth.rs:105`). The sequence:

1. Derive `hmac_key` from the node's Ed25519 signing key.
2. Try to load a still-valid token from `~/ZeroPoint/session.json`.
   If found (same key fingerprint, within `max_age_secs`), reuse it.
3. Otherwise mint a fresh token and write it to disk atomically (0600).

`zp configure exec` issues **nothing**. It unlocks the vault via
`load_sovereign_root()` (one Touch ID prompt), resolves tool env vars
from the vault, emits a launch receipt, then calls `exec()` — and does
not touch `session.json` at all. The child process inherits whatever env
it had, which has no `ZP_SESSION_TOKEN`.

The Hermes `zp-governance` plugin (`services/hermes-plugins/zp-governance/__init__.py:58`)
already handles this gracefully: it reads `ZP_SESSION_TOKEN` from env,
falls back to `_SESSION_FILE = Path.home() / "ZeroPoint" / "session.json"`.
IronClaw's built-in ZP governance hook reads `ZP_SESSION_TOKEN` from
env only (no file fallback), which is why the walk-through failed: no
env var → no Bearer header → 401 from the gate → IronClaw blocks the
tool call.

---

## 3. Where does the token live between issuance and use?

```
~/ZeroPoint/session.json   (written by `zp serve` at startup, 0600)
    |
    ├── read by: Hermes zp-governance plugin (file fallback path)
    ├── read by: agui-proxy (file fallback path)
    └── read by: zp configure exec [PROPOSED: inject as ZP_SESSION_TOKEN]
                    |
                    └── ZP_SESSION_TOKEN env var in child process
                            |
                            └── IronClaw ZP hook → Authorization: Bearer <token>
                                    |
                                    └── /api/v1/gate/tool-call (zp-server, port 17010)
```

The file schema (`PersistedSession`, `auth.rs:42`):

```json
{ "token": "<64-char hex>", "created_at": 1747234800, "key_fp": "<16-char hex>", "version": 1 }
```

`key_fp` is `hex(SHA-256(hmac_key)[..8])` — used at restart to detect
identity rotation. The file is always at `zp_paths::session_path()`,
which is `~/ZeroPoint/session.json` (confirmed `paths.rs:161`).

---

## 4. What does the cognition-governance hook check?

The gate endpoint `POST /api/v1/gate/tool-call` (`lib.rs:1060`) sits
behind the global `require_auth` middleware (`lib.rs:1116–1129`). The
middleware is not exempt for this path (`is_exempt()` covers only health,
version, onboard, lease/renew, fleet/heartbeat, assets — `auth.rs:532`).

Auth priority order (`auth.rs:578`):
1. `Authorization: Bearer <token>` header
2. `Cookie: zp_session=<token>`
3. `?token=<token>` — WebSocket paths only

The middleware calls `session_auth.verify(candidate)` which:
- Checks wall-clock age against `max_age_secs` (default 8 h)
- Constant-time-compares candidate against the server's single live token
- Returns 401 with `{"error":"unauthenticated"}` on missing token,
  401 with `{"error":"session_stale"}` on present-but-invalid token

The gate handler itself (`lib.rs:3182`) checks: lease halt flag, agent
standing delegation prerequisite (if `req.agent` is set), then the
deny-list at `~/ZeroPoint/gate-policy.json`. Auth is not re-checked in
the handler body — the middleware is the auth boundary.

What IronClaw's hook wraps this with: IronClaw interprets a 401 response
from the gate as a hard block with the message
`"ZP gate authentication failed (status 401). Cannot govern this tool call.
Re-onboard or refresh ZP_SESSION_TOKEN, then retry."` — this is
IronClaw's own fail-closed posture, not a ZP server message.

---

## 5. How the token derives from Genesis (singular root compliance)

```
Genesis (Ed25519 seed, 32 bytes)
  └─ Keyring signing_key  (Ed25519 private key, loaded from keys/ dir)
       └─ hmac_key = SHA-256(signing_key_bytes || "zp-session-v1")
            └─ session_token = hex(SHA-256(hmac_key || nonce || ts_le))
                 └─ ~/ZeroPoint/session.json  (0600, written by zp-server)
                      └─ read by exec → ZP_SESSION_TOKEN in child env
```

The session token is a one-way projection of Genesis through the signing
key. It cannot be forged without the signing key. A new token cannot be
minted by exec independently because `SessionAuth::verify` compares
against the single live token the server holds — an independently-minted
token with a different nonce would fail verification even though it is
derived from the same key material. Therefore exec must read the token
that the server already wrote, not mint a new one.

**Singular root constraint is satisfied:** the vault unlock (`load_sovereign_root()`)
is the one authentication ceremony per exec invocation. Reading
`session.json` afterward is a file read, not a second credential-store
access. No new Keychain item is created. The discipline pin
`singular_sovereign_root` is not tripped (it fires on direct
credential-store reads outside `sovereignty/`, not on file reads).

---

## 6. TTL and refresh semantics

| Parameter | Value | Source |
|-----------|-------|--------|
| Default TTL | 8 hours | `auth.rs:129` |
| Override | `ZP_SESSION_MAX_AGE_SECONDS` env var | `auth.rs:126` |
| Refresh | Server restart or explicit `/logout` → `session_auth.rotate()` | `auth.rs:197` |
| Exec posture | Read-at-launch — no refresh during exec lifetime | (proposed) |

For the PoC use case (a single session of < 8 h), no refresh path is
needed. For long-lived exec contexts (leaving IronClaw open overnight),
the token will expire and IronClaw will start getting 401s. That
matches the "re-onboard or refresh" message IronClaw already shows and
is explicitly out of scope per the brief.

If refresh is needed later: exec could re-read `session.json` and signal
the child to reload via a sidecar or periodic env injection. That is a
separate problem and should not be designed here.

---

## 7. Why `zp configure exec` is the right issuer vs alternatives

**Option A: `zp session start` command (separate issuance step)**
Requires a manual step before every exec launch. Adds ceremony the
operator didn't ask for. The token is already on disk from `zp serve`
startup — there is nothing to "start."

**Option B: exec mints a fresh token independently**
Cryptographically possible (exec has the signing key), but functionally
wrong: the server holds exactly one valid token at a time. A
fresh-minted token with a different nonce fails `SessionAuth::verify`.
This path would require the server to validate by re-deriving
(whitelist-by-key-material rather than compare-single-token), a non-trivial
change to auth.rs with broader security implications. Not appropriate
for a targeted fix.

**Option C: server exposes a "get my token" endpoint**
Circular: the endpoint would be auth-protected by the token you're
trying to get. The server could have a local-only unprotected endpoint
for token retrieval, but this opens a SSRF-adjacent surface. Unnecessary
when the file already exists.

**Option D: exec reads `session.json` and injects as env var (proposed)**
Minimal. No new code path in the server. No new Keychain item. Respects
singular root. Consistent with how agui-proxy and the Hermes plugin
already consume the token. The exec command already has the operator's
trust context (vault unlocked, launch receipt emitted) — reading a
0600 file in `~/ZeroPoint/` is within that context.

---

## 8. Implementation surface

### Files to touch

| File | Change |
|------|--------|
| `crates/zp-cli/src/main.rs` | In `ConfigureCmd::Exec` handler (line ~1440), after `env_map` is populated, read `zp_paths::session_path()`, parse the JSON, extract `token`, call `child.env("ZP_SESSION_TOKEN", token)` |
| `crates/zp-cli/src/main.rs` | Add a non-fatal warning if `session.json` is absent or unreadable (server not running) — `eprintln!` only, do not block launch |

No changes to `zp-server`, `auth.rs`, or any sovereignty module.
No new Keychain item. No new crate dependency (file I/O + serde_json
already in scope).

### Exact insertion point

Between the `for (k, v) in &env_map { child.env(k, s); }` loop (line ~1443)
and the `child.exec()` call (line ~1453). After vault vars are injected,
before the process image is replaced.

```rust
// Inject ZP session token so gov hook can authenticate.
// Reads ~/ZeroPoint/session.json written by `zp serve` at startup.
// Non-fatal if server not running — IronClaw will degrade gracefully.
if let Ok(tok) = read_zp_session_token() {
    child.env("ZP_SESSION_TOKEN", tok);
} else {
    eprintln!("  ⚠  ZP session not found — gov hook will lack credentials.");
    eprintln!("     Is `zp serve` running?");
}
```

`read_zp_session_token()` is a two-line helper (private to the exec arm):

```rust
fn read_zp_session_token() -> Result<String, Box<dyn std::error::Error>> {
    let path = zp_core::paths::session_path()?;
    let s = std::fs::read_to_string(path)?;
    let v: serde_json::Value = serde_json::from_str(&s)?;
    v["token"].as_str().map(|t| t.to_string())
        .ok_or_else(|| "no token field".into())
}
```

No new public API surface. No new module. No abstraction added.

---

## 9. Tests

The test-discipline lesson from #154: function-isolation tests do not
catch path-shape regressions. Integration coverage is required.

### Integration test: exec injects valid token (new)

Location: `crates/zp-hardening-tests/tests/` (new file
`phase_session_token_inject.rs` or appended to an existing phase file).

Shape:
1. Spin up `zp-server` via the existing test harness.
2. Capture `state.session_token()` — this is the live token the server holds.
3. Read `~/ZeroPoint/session.json` (or the harness's temp path) and assert
   the file's `token` field matches `state.session_token()`.
4. POST to `/api/v1/gate/tool-call` with `Authorization: Bearer <token>`.
   Assert 200 + `{"allow": true}`.
5. POST without any Authorization header. Assert 401.
6. Exercise the real exec path: build the `child` Command the exec handler
   would build, verify `ZP_SESSION_TOKEN` is present in its env and equals
   the server's token. (No actual `exec()` needed — inspect the `Command`
   object before spawning.)

### Unit test: `read_zp_session_token` round-trip (new)

Write a tempfile with a valid `PersistedSession` JSON, call
`read_zp_session_token()` pointed at it, assert the token is returned.
Write a tempfile with missing `token` field, assert it returns `Err`.

### Regression: exec without server running

Mock: `session.json` absent (delete after test, restore after). Assert
exec proceeds (non-fatal), child is spawned, `ZP_SESSION_TOKEN` is absent
from the child env. This guards against the "gate not running = exec
blocks" regression.

### End-to-end shape (manual / PoC retest)

```
zp serve &                         # writes session.json
zp configure exec --name ironclaw -- ironclaw
# IronClaw chat: @chain_render
# Expected: tool completes, receipt emitted, chain narrated
```

This is the PoC #147 acceptance run.

---

## 10. What is NOT being designed here

- A new token format — the existing format is correct and sufficient
- Token refresh in long-lived exec sessions (deferred, out of scope)
- Multi-agent or cross-process token sharing (each exec gets its own injection)
- Changes to IronClaw's ZP hook behavior (it correctly reads from env)
- Changes to the gate handler auth policy (the middleware is correct)
- A `zp session` subcommand (unnecessary given file-based issuance works)

---

## Refs

- `crates/zp-server/src/auth.rs` — `SessionAuth`, `mint_token`, `verify`, `persist_session`
- `crates/zp-server/src/lib.rs:1060` — gate route registration
- `crates/zp-server/src/lib.rs:1116` — auth middleware wiring
- `crates/zp-server/src/lib.rs:3168` — `gate_tool_call_handler`
- `crates/zp-cli/src/main.rs:1324` — `ConfigureCmd::Exec` handler
- `crates/zp-core/src/paths.rs:161` — `session_path()`
- `services/hermes-plugins/zp-governance/__init__.py:58` — `_session_token()` fallback pattern
- `docs/ARCHITECTURE-2026-05.md §II.21` — singular sovereign root
- `docs/handoffs/zp-session-token-issuance-2026-05.md` — the brief this answers
- Task #147 — PoC blocked on this
