# Handoff — Comet Browser Cookie Delivery Investigation

*2026-05-15. Target: terminal Claude. Diagnostic investigation, no
code changes in this round. Output is a design one-pager identifying
root cause and proposing the fix shape.*

## Goal

Determine why `zp_session` cookie is set correctly at
`app.zeropointfoundation.org` (visible in Comet DevTools) but doesn't
reach IronClaw's localhost gateway when the browser makes requests.
curl with explicit `-b cookie_header` works; browser path fails. After
this lands, fix `zp_session` cookie delivery so chain commands from
the browser succeed end-to-end without curl scaffolding.

## Evidence

- Comet DevTools shows `zp_session=...` cookie set with `Domain=.zeropointfoundation.org`
- Request from Comet to `https://app.zeropointfoundation.org/api/...` does NOT include the cookie in the request headers
- `curl -b "zp_session=..." https://app.zeropointfoundation.org/...` works and returns expected auth-passed response
- IronClaw is exposed via Cloudflare Tunnel, terminating at `app.zeropointfoundation.org`
- Substrate-session HMAC bridge (#138) is verified working on the worker side; the bridge isn't the problem
- Symptom presents in Comet specifically; not confirmed whether Safari/Chrome reproduce

## Likely investigation surface

The cookie is set; it's not being sent. Three classes of root cause:

1. **Cookie scope mismatch.** Maybe the cookie is set with `Domain=zeropointfoundation.org` but Comet treats `app.zeropointfoundation.org` as a different effective scope. Inspect actual cookie attributes (Domain, Path, Secure, HttpOnly, SameSite) via DevTools. Compare to what the foundation worker is issuing via `Set-Cookie` headers (`zeropointfoundation.org/src/auth/session.js`).

2. **SameSite enforcement.** Comet may apply strict SameSite enforcement that other browsers relax for localhost. If the cookie is `SameSite=Lax` or `Strict` and the request flow involves a redirect or cross-origin transition, Comet might withhold it.

3. **Comet-specific localhost isolation.** Some browsers treat localhost as a separate origin family for cookie scoping (privacy feature). Worth checking Comet's documented behavior — does Comet have a localhost cookie isolation feature?

Diagnostic commands the investigation should run:

```sh
# 1. Capture the actual Set-Cookie header the worker issues
curl -v -c /tmp/cookie-jar https://zeropointfoundation.org/api/auth/session 2>&1 | grep -i "set-cookie"

# 2. Inspect the cookie jar contents
cat /tmp/cookie-jar

# 3. Confirm curl forwards it correctly
curl -v -b /tmp/cookie-jar https://app.zeropointfoundation.org/api/operator/me/chain 2>&1 | grep -i "cookie:"

# 4. Repeat the browser flow in Safari or Chrome — does the cookie deliver there?
#    If yes → Comet-specific
#    If no → cookie scoping or worker issuance problem

# 5. Check the foundation worker's cookie issuance code
rg -n "Set-Cookie|setCookie|cookie\." zeropointfoundation.org/src/auth/
```

## Deliverable

`docs/handoffs/comet-cookie-delivery-design-2026-05.md` covering:

1. The exact `Set-Cookie` header the worker issues (capture verbatim)
2. Comet's actual handling of that cookie (DevTools screenshot or transcription of cookie attributes as Comet displays them)
3. Whether Safari/Chrome/Firefox exhibit the same symptom (one of these tests is sufficient — pick whichever is convenient)
4. Root cause classification: cookie scope, SameSite policy, Comet-specific isolation, or something else
5. Proposed fix shape:
   - Worker-side change (adjust cookie attributes — Domain, SameSite, Path)
   - Browser-side workaround (operator instruction for Comet config if needed)
   - Architectural change (e.g., explicit operator sign-in surface from #156 to avoid cookie-passing entirely)
6. Risk surface — does the fix interact with the operator sign-in surface (#156) design, the substrate-as-sovereign-IdP work (#139), or anything else queued

Don't write the fix code in this round. Diagnose, propose, bring back for review.

## Acceptance criteria

After this lands:

1. Root cause identified empirically (not just hypothesized)
2. Proposed fix is scoped to either worker-side cookie attribute change OR documented Comet config workaround OR architectural redesign — pick the path the evidence supports
3. Other browsers' behavior documented (Safari at minimum) to confirm whether the issue is Comet-specific
4. Connection to #149 (IronClaw re-prompt loop) explicitly assessed — same root cause, related, or independent

## Out of scope

- Implementing the fix (separate task after design review)
- Switching browsers as a permanent solution (Comet is operator's daily driver; the substrate should work in Comet)
- Operator sign-in surface design (#156) — that's the architectural answer if cookies aren't the right transport at all, but we resolve cookie delivery first before deciding to redesign

## Refs

- Task #164 (this work)
- Task #138 (substrate-session bridge — the cookie's purpose)
- Task #149 (IronClaw re-prompt loop — possibly related)
- Task #156 (operator sign-in surface — architectural fallback if cookie transport is the wrong model)
- `zeropointfoundation.org/src/auth/session.js` — cookie issuance code
- `crates/ironclaw-*/src/channels/web/platform/auth.rs` — substrate-session verification on IronClaw side
