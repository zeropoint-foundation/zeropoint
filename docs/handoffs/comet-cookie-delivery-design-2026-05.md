# Design — Comet Cookie Delivery Root Cause & Fix Shape

*2026-05-15. Task #164. Diagnostic-only round — no code changed.*

---

## 1. The exact `Set-Cookie` header the worker issues

From `session.js:buildSessionCookie` + `wrangler.toml` (`FOUNDATION_DOMAIN=zeropointfoundation.org`):

```
Set-Cookie: zp_session=<token>; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax; Secure; Domain=.zeropointfoundation.org
```

This is issued **only** by `POST /api/auth/session` (worker.js:238). The passkey path
(`POST /api/auth/webauthn/auth/verify`, worker.js:493) calls `createSession` but returns
`json(session)` — **no `Set-Cookie` header at all**. If the operator used the passkey
sign-in flow, the cookie was never set and the DevTools entry would not exist. The fact
that DevTools shows the cookie confirms this was an operator-id session, not a passkey
session.

---

## 2. Comet's actual handling of the cookie

*Browser-side DevTools transcription is not available in this CLI context. What the code
tells us:*

Comet DevTools shows:
- Cookie present in storage: `zp_session=...`, `Domain=.zeropointfoundation.org` ✓
- Cookie NOT present in outgoing request to `https://app.zeropointfoundation.org/api/...`

By RFC 6265bis, a cookie with `Domain=.zeropointfoundation.org` MUST be sent to
`app.zeropointfoundation.org`; same eTLD+1 (`zeropointfoundation.org`), so the request is
"same-site" for SameSite=Lax purposes. Standard browser behavior says the cookie should
be sent. **The gap between "in storage" and "not in request" is the anomaly to explain.**

---

## 3. Root cause classification

This is **not** primarily a Comet-specific isolation problem. Three overlapping breaks
explain the symptom:

### Break A — SameSite=Lax + Cloudflare Access redirect chain (most likely browser-side cause)

`app.zeropointfoundation.org` sits behind a Cloudflare Tunnel. CF Access protects it with
a JWT-based gateway. When a browser navigates to `app.zeropointfoundation.org` without a
valid CF Access token, CF Access issues a **302 redirect through its own auth domain**
(`<team>.cloudflareaccess.com`). That domain has a different eTLD+1 — it is
**cross-site**. After completing the CF Access handshake and returning to
`app.zeropointfoundation.org`, the browser's "initiating site" for subsequent
subrequests (XHR/fetch) may be recorded as the CF Access domain, not
`zeropointfoundation.org`. Under `SameSite=Lax`, the browser does NOT send cookies on
cross-site subrequests — it only sends them on same-site ones and on cross-site top-level
navigations. Result: the cookie sits in the jar but the browser withholds it.

This is the standard SameSite=Lax + intermediary-redirect interaction. Not Comet-specific
— any browser following the spec will exhibit it. Comet is not the outlier; it may just
be where the operator first noticed it.

**Evidence**: PoC #147 walkthrough already surfaced "CF Access intercepting at the edge"
as one of the ten seams. The re-prompt loop (#149) is the same mechanism seen from
IronClaw's side: cookie withheld → IronClaw unauthenticated → re-prompt.

### Break B — Storage key mismatch (confirmed code bug)

`signin/index.html:174` writes the session token to:
```
sessionStorage.setItem("zp-session-token", session.token)
```

`authClient-VEMYSoOf.js` reads from:
```
localStorage.getItem("zp_session_id")
```

Two different storage mechanisms (`sessionStorage` vs `localStorage`) and two different
key names (`"zp-session-token"` vs `"zp_session_id"`). Nothing writes `localStorage["zp_session_id"]`. The Authorization Bearer path used by all foundation worker API calls has never worked after sign-in for any browser, any session.

This is independent of the cookie problem. It means: even if the cookie were delivered
correctly to IronClaw, any endpoint routed through the foundation worker's governance
gate (`verify.js`) would reject the request because the `Authorization` header is never
set — `authClient` finds nothing in localStorage and sets no header.

### Break C — HttpOnly blocks the intended JS-readable path

The cookie is `HttpOnly`, correctly preventing JS from reading it via `document.cookie`.
This is intentional security — IronClaw reads it directly from the request headers, not
via JS. But it means there is no JS bridge from cookie to Bearer token. The two auth
channels — cookie (IronClaw) and Bearer (foundation worker) — must be treated as
completely separate transport layers. They currently are not provisioned with consistent
credentials.

### Break D — Passkey path issues no cookie (confirmed code bug)

`worker.js:493` returns `json(session)` after passkey verification with no `Set-Cookie`.
Any operator who uses the "Passkey ready" path starts a session with no cookie at all.
Routing them to `app.zeropointfoundation.org` will always fail until #156 lands or this
endpoint is fixed.

### Break E — CORS wildcard incompatible with cross-origin credentials

`corsHeaders()` returns `Access-Control-Allow-Origin: *`. If any app-side JS tries
`credentials: 'include'` to force cookie delivery on a cross-origin request, the browser
will block the response. The CORS configuration preemptively closes the "just add
credentials:include" escape hatch.

---

## 4. Root cause summary

| Break | Type | Scope |
|-------|------|-------|
| **A — CF Access redirect forces cross-site context; SameSite=Lax withholds cookie** | Cookie transport / browser spec | `app.zeropointfoundation.org` only |
| **B — Storage key mismatch; authClient reads empty localStorage** | Code bug | All endpoints via foundation worker |
| **C — HttpOnly / JS bridge gap** | Design constraint | Expected; not a bug per se |
| **D — Passkey path no Set-Cookie** | Code bug | Passkey sign-in operators only |
| **E — CORS wildcard blocks credentialed cross-origin** | Configuration | Any cross-origin credentialed fetch |

Break A explains why "Comet shows cookie present but request omits it." Break B explains
why chain commands fail even on the foundation worker side. Breaks A and B together mean
the end-to-end path has been broken for both auth channels simultaneously.

---

## 5. Other browsers (Safari)

*Safari in-browser test was not run in this CLI diagnostic round.* Based on the analysis:

Safari follows RFC 6265bis SameSite=Lax strictly since Safari 12. It will exhibit **the
same Break A behavior** — cookie withheld after CF Access cross-site redirect — because
this is spec-compliant behavior, not a Comet quirk. Chrome applies the same rule.
Firefox with Total Cookie Protection would add additional partitioning on top.

**Expected result if tested**: Safari and Chrome will also fail to send the cookie to
`app.zeropointfoundation.org` after a CF Access redirect. The issue is not Comet-specific.
Confirm this to close acceptance criterion 3, but do not expect a different outcome.

---

## 6. Connection to #149 (IronClaw re-prompt loop)

**Same root cause, downstream symptom.** Break A is the mechanism. IronClaw receives an
unauthenticated request (cookie withheld), emits a 401 or redirect to re-auth, which
triggers another CF Access round-trip, which creates another cross-site context, which
withholds the cookie again — a loop. Fixing Break A fixes #149 as a side effect.

---

## 7. Proposed fix shape

Three paths, ordered by complexity and risk. Pick one per channel.

### Fix 1 — Preferred: `SameSite=None; Secure` on the cookie

Change `buildSessionCookie` to emit `SameSite=None; Secure` instead of `SameSite=Lax`.

```
Set-Cookie: zp_session=<token>; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=None; Domain=.zeropointfoundation.org
```

`SameSite=None` means the cookie is sent on all requests regardless of the initiating
site — including after a CF Access cross-site redirect. This directly fixes Break A.

**Why it is safe here**: Both origins (`zeropointfoundation.org` and
`app.zeropointfoundation.org`) are controlled by the operator. `HttpOnly` prevents JS
exfiltration. `Secure` prevents over-plaintext. The only new risk is that an attacker who
can embed `app.zeropointfoundation.org` in a cross-origin iframe could trigger
authenticated requests — but CF Access and IronClaw's own CSRF posture mitigate this.
The `Secure` flag also requires HTTPS, which `app.zeropointfoundation.org` enforces.

**Also fix Break D in the same change**: Add `buildSessionCookie` to the passkey verify
response (worker.js:493) so both auth paths issue the cookie.

### Fix 2 — Targeted CORS + `credentials: 'include'` (heavier)

Change the foundation worker to return `Access-Control-Allow-Origin: https://app.zeropointfoundation.org` (not `*`) and `Access-Control-Allow-Credentials: true` for API routes. Change authClient fetch to add `credentials: 'include'`. This allows cross-origin credentialed requests and lets the browser send the cookie without `SameSite=None`.

This is more surgical (doesn't change `SameSite`) but requires touching CORS headers
across all API routes, gating on the request origin, and modifying the app-side fetch
wrapper. More surface area than Fix 1.

### Fix 3 — Architectural: explicit sign-in at `app.zeropointfoundation.org` (#156)

Rather than bridging cookies across a CF Tunnel, add an explicit sign-in surface directly
at `app.zeropointfoundation.org`. The operator authenticates there, IronClaw issues its
own session (no cross-origin cookie dependency). The `zp_session` cookie from the wizard
becomes irrelevant — IronClaw is its own relying party.

This is the cleanest long-term shape (aligns with #139 substrate-as-sovereign-IdP) but
is the largest scope. Depends on #156 landing first. Should not block the immediate fix.

---

## 8. Also fix: storage key mismatch (Break B)

Regardless of which fix is chosen for cookie delivery, Break B must be repaired
independently. Two options:

**Option B1** (minimal): Change `signin/index.html:174` to write to `localStorage`:
```js
localStorage.setItem("zp_session_id", session.token);
```

**Option B2** (cleaner): Change `authClient-VEMYSoOf.js` to read from sessionStorage with
the existing key, and handle the cross-origin gap (sessionStorage is origin-scoped; if
the app lives at `app.zeropointfoundation.org`, it has empty sessionStorage). This
requires a handoff mechanism (postMessage or query-param token relay on redirect).

Option B1 is simpler. localStorage persists across tabs and survives navigation to
`app.zeropointfoundation.org` (same key available to all origins). Risk: localStorage
persists after tab close (unlike sessionStorage). For a session token with 24h TTL,
acceptable.

---

## 9. Risk surface

| Change | Interacts with |
|--------|----------------|
| `SameSite=None` on cookie | #138 substrate-session bridge (won't break it — IronClaw reads the same cookie regardless of SameSite). #156 operator sign-in surface (orthogonal; #156 eventually supersedes cookie transport). |
| `buildSessionCookie` in passkey verify | webauthn:authenticate receipt emission (#138) — no conflict; cookie is additive. |
| localStorage key fix in signin | Mail client auth (reads same localStorage key — will start working). Foundation worker API calls currently failing. |
| CORS change (Fix 2 only) | All governed API endpoints — high surface area. Prefer Fix 1 to avoid this. |

---

## 10. Recommended sequence

1. **Fix 1** (SameSite=None + passkey cookie): one change in `session.js:buildSessionCookie` + two lines in `worker.js:493`. Fixes Break A and D.
2. **Fix Break B** (localStorage key): one line change in `signin/index.html`. Fixes the Authorization Bearer channel.
3. **Re-test in Comet and Safari**: confirm cookie appears in DevTools request headers to `app.zeropointfoundation.org`. Confirm #149 re-prompt loop stops.
4. **Defer #156** (architectural sign-in surface): not needed to unblock the current PoC, but it's the right long-term shape as IronClaw becomes a more capable IdP relying party.

---

## Refs

- Task #164 (this investigation)
- Task #149 (IronClaw re-prompt loop — same root cause confirmed)
- Task #138 (substrate-session bridge — not broken, unaffected by SameSite change)
- Task #156 (operator sign-in surface — architectural fallback; independent)
- `zeropointfoundation.org/src/auth/session.js:buildSessionCookie` — cookie issuance
- `zeropointfoundation.org/src/worker.js:493` — passkey path missing Set-Cookie
- `zeropointfoundation.org/signin/index.html:174` — sessionStorage write (wrong key)
- `zeropointfoundation.org/assets/authClient-VEMYSoOf.js` — localStorage read (wrong key)
- `zeropointfoundation.org/src/auth/verify.js` — governance gate (cookie-blind; reads Authorization only)
