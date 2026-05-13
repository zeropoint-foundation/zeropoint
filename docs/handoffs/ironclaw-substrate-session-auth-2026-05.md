# Handoff — IronClaw gateway: substrate-session-token auth path

*2026-05-12. Target: terminal Claude working in `~/projects/ironclaw` on
the `zp-daily-driver` branch. Refs: #138 part 2, #139 (the eventual proper
shape this is a bridge to).*

## Goal

Add a third authentication path to the IronClaw gateway: read the
`zp_session` cookie from incoming requests, HMAC-verify it against a
shared signing key, extract the operator context, allow the request
through. This replaces Cloudflare Access OIDC as the auth gate for
`app.zeropointfoundation.org` and lets the substrate be the sole
identity layer for the foundation pilot.

## Why it matters

ZeroPoint's core claim is *portable trust* — identity that doesn't
depend on big-tech infrastructure providers. Cloudflare Access in
front of `app.zp.org` is belt-and-suspenders that doesn't compose: it
forces directors to re-prove identity at the edge (email-OTP) after
they already proved it cryptographically in the wizard. Removing it
makes the substrate the actual identity authority, which is the whole
thesis.

This work is the *bridge* shape (HMAC shared secret between the worker
and IronClaw). The *proper* shape is #139 (substrate as its own OIDC
IdP, JWKS, no shared secret). #139 lands later; this gets the pilot
moving now.

## What's already done (wizard side)

Commit on `main` of `zeropoint-foundation/zeropoint`:
- `zeropointfoundation.org/src/auth/session.js` — exports
  `SESSION_COOKIE_NAME = "zp_session"`, `buildSessionCookie()`,
  `clearSessionCookie()`. Session tokens are HMAC-SHA256 signed using
  `env.SESSION_SIGNING_KEY`.
- `zeropointfoundation.org/src/worker.js` — `POST /api/auth/session`
  now also returns `Set-Cookie: zp_session=...; Domain=.zeropointfoundation.org;
  HttpOnly; Secure; SameSite=Lax; Max-Age=86400` (host-scoped on
  localhost, no Secure on http).

The browser carries this cookie to `app.zeropointfoundation.org`
automatically on the wizard handoff click. IronClaw just has to read it.

## Token format (read this carefully)

Source of truth: `zeropointfoundation.org/src/auth/session.js`.

```
token := <payload_b64> "." <sig_b64>

payload      := JSON({ sub, name, cap, iat, exp })
payload_b64  := base64url(payload)
sig          := HMAC-SHA256(SESSION_SIGNING_KEY, payload_b64)
sig_b64      := base64url(sig)
```

`base64url` is standard base64 with `+` → `-`, `/` → `_`, trailing `=`
stripped. NOT padded.

Verification (mirror the JS in `verifySession()`):

1. Split token on first `.` — left is `payload_b64`, right is `sig_b64`.
2. Compute expected sig = base64url(HMAC-SHA256(KEY, payload_b64)).
3. Constant-time compare expected_sig to sig_b64. Mismatch → 401.
4. Decode payload_b64 as base64url → UTF-8 JSON.
5. Check `Date.now() > payload.exp` → 401 expired.
6. Extract: `operator_id = payload.sub`, `name = payload.name`,
   `capabilities = JSON.parse(payload.cap)` (it's a JSON-string-in-a-
   string in the operator row).
7. Allow request through with operator context attached.

## Where in IronClaw

Auth happens in the gateway middleware. Relevant files:

- `src/config/channels.rs` — Gateway config struct (currently has
  `oidc: Option<GatewayOidcConfig>` and `auth_token: Option<String>`).
  Add a parallel `substrate_session: Option<SubstrateSessionConfig>`
  with `enabled` flag and `signing_key` (loaded from env).
- `src/channels/web/...` — gateway HTTP handler. Find where the
  current OIDC verification + bearer-token check happens. Add the
  substrate-session check as a third path that runs *before* OIDC
  (it's cheaper and is the new primary path).
- `src/channels/web/tests/bearer_oidc.rs` — there's already a test
  pattern for OIDC bearer auth here. Add `bearer_substrate.rs` (or
  similar) with the new auth path's tests.

## Env vars to add

In `.env.example` + `.env.zp`:

```
# Substrate session auth — verify HMAC-signed tokens issued by the
# zeropointfoundation.org worker. Must match the worker's
# SESSION_SIGNING_KEY exactly (same secret on both sides).
GATEWAY_SUBSTRATE_SESSION_ENABLED=true
GATEWAY_SUBSTRATE_SESSION_KEY=<paste from worker secret>
GATEWAY_SUBSTRATE_SESSION_COOKIE_NAME=zp_session
```

Reading order: check cookie `zp_session` first. If present and valid,
operator is authenticated. If missing/invalid, fall through to other
auth paths (OIDC, bearer token).

## Key sharing

`SESSION_SIGNING_KEY` in the worker secrets (Cloudflare) and
`GATEWAY_SUBSTRATE_SESSION_KEY` in IronClaw's `.env` must be byte-
for-byte identical. Generate a fresh 32+ byte random value with
`openssl rand -base64 32`, set it in both places (Ken does this
manually — both ends are in his control). Document the rotation
procedure in a comment near the env var.

## Acceptance criteria

1. With `GATEWAY_SUBSTRATE_SESSION_ENABLED=false`, gateway behaves
   exactly as today (OIDC path + GATEWAY_AUTH_TOKEN unchanged). No
   regression.
2. With `GATEWAY_SUBSTRATE_SESSION_ENABLED=true` and a matching
   signing key, a request carrying a valid `zp_session` cookie passes
   auth; operator id is extracted into the request context.
3. Invalid signature → 401. Expired token → 401. Missing cookie + no
   other auth → falls through to existing paths (or 401 if none).
4. New unit tests for the HMAC verifier (good token, bad sig, expired,
   malformed).
5. New integration test mirroring `bearer_oidc.rs` shape but for the
   cookie path.
6. `cargo check --workspace` clean. Existing tests still pass.

## Out of scope (do NOT do in this pass)

- Removing the OIDC verification path. Leave it alongside. We're
  *adding* an auth method, not replacing the existing one yet.
- Changing the CF Access dashboard config. Ken does that step
  manually after IronClaw can authenticate via the new path.
- Implementing the OIDC-IdP shape (#139). That's the next architectural
  pass; this one is the HMAC bridge.

## After this lands

Ken's checklist:
1. Generate a shared signing key.
2. Set it as worker secret (`wrangler secret put SESSION_SIGNING_KEY`)
   and in IronClaw's `.env` (`GATEWAY_SUBSTRATE_SESSION_KEY=...`).
3. Restart both.
4. Disable the Cloudflare Access application for `app.zeropointfoundation.org`.
5. Pilot the wizard end-to-end: complete onboarding at
   `zeropointfoundation.org/onboard/`, click the handoff, land directly
   in IronClaw at `app.zp.org` — no email-OTP challenge.

Then the substrate is the sole identity layer for the foundation. The
core claim becomes load-bearing instead of decorative.
