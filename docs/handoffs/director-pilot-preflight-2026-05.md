# Director Pilot — Preflight Checklist

*2026-05-13. Captured immediately after the Ken-pilot. Each item on
this list represents a friction we hit on the first end-to-end run.
Running through this checklist before sitting an actual director down
is the difference between a 30-minute ceremony and a half-day
debugging session.*

## How to use this

Run through the boxes in order. None should take more than a minute
or two to verify. Stop and fix anything that doesn't pass before
inviting the director.

The director walking through should be on a clean device with no
prior cookies for `*.zeropointfoundation.org` — fresh private window
is the easiest way.

---

## Substrate (zeropointfoundation.org worker)

### 1. Production D1 has all migrations applied

```sh
cd ~/projects/zeropoint/zeropointfoundation.org
npx wrangler d1 migrations apply zpmail --remote
```

If it says "no migrations to apply," you're current. If it lists
pending migrations, apply them and re-verify with another run.

Why this matters: local D1 and remote D1 maintain independent
migration state. Running `--local` does not propagate to `--remote`.
The Ken-pilot hit a 500 on Phase 5 (passkey) because migrations 0007
+ 0008 were never applied to production.

### 2. Foundation worker owns the foundation routes

In the Cloudflare dashboard, confirm:
- `zeropointfoundation.org/*` → bound to `zeropoint-foundation`
- `www.zeropointfoundation.org/*` → bound to `zeropoint-foundation`
- Neither of these routes is still claimed by `zeropoint-global` or
  any other worker

If wrong: in the dashboard, find the worker incorrectly claiming the
route and delete that route from its Triggers/Domains list. Then
`npx wrangler deploy` from `zeropointfoundation.org/` to bind the
correct worker.

Why this matters: `zeropoint-foundation` had been in source for weeks
before today but had never deployed to production because
`zeropoint-global` was still claiming the routes. We discovered this
mid-pilot.

### 3. SESSION_SIGNING_KEY set on the worker

```sh
cd ~/projects/zeropoint/zeropointfoundation.org
npx wrangler secret list
```

Should show `SESSION_SIGNING_KEY` in the list. If missing:

```sh
KEY=$(openssl rand -base64 32)
echo "Key: $KEY"
npx wrangler secret put SESSION_SIGNING_KEY
# paste $KEY into the prompt — DO NOT pipe via echo (trailing newline)
```

Keep $KEY visible — you need to paste the same value into IronClaw's
`.env` (step 6 below).

### 4. Latest wizard + assets deployed

```sh
cd ~/projects/zeropoint/zeropointfoundation.org
npx wrangler deploy
```

Confirm the deploy log mentions the routes are bound:
```
  zeropointfoundation.org/* (zone name: zeropointfoundation.org)
  [www.zeropointfoundation.org/*]
```

Then smoke-test that key assets are reachable:

```sh
curl -I https://zeropointfoundation.org/onboard/
curl -I https://zeropointfoundation.org/onboard/onboarding-voice-palette.json
curl -I https://zeropointfoundation.org/onboard/voices/bm_daniel-sample.mp3
```

All three should return `HTTP/2 200` with appropriate `content-type`
headers. If any return 404, the asset wasn't deployed — re-run the
deploy and verify the file is actually in `zeropointfoundation.org/`.

---

## Cloudflare Access

### 5. Access application for app.zeropointfoundation.org is removed

In the Cloudflare dashboard, navigate to:
**Zero Trust → Access Controls → Applications**

Should NOT show an application for `app.zeropointfoundation.org`. If
it does, delete it (three-dot menu → Delete).

Why this matters: any Access application in front of `app.zp.org`
forces a second auth challenge (email-OTP or otherwise) on the
director after they complete substrate-session onboarding. The whole
point of the architecture is to be the sole identity layer.

---

## IronClaw (gateway)

### 6. SESSION_SIGNING_KEY in IronClaw's env, matching the worker

```sh
grep GATEWAY_SUBSTRATE_SESSION ~/.ironclaw/.env
```

Should show three uncommented lines:

```
GATEWAY_SUBSTRATE_SESSION_ENABLED=true
GATEWAY_SUBSTRATE_SESSION_KEY=<exact same value as $KEY from step 3>
GATEWAY_SUBSTRATE_SESSION_COOKIE_NAME=zp_session
```

The signing key must be byte-identical to the worker secret. Even a
trailing newline difference will fail HMAC verification.

### 7. IronClaw binary is current

```sh
cd ~/projects/ironclaw
git fetch foundation
git pull foundation zp-daily-driver
cargo build --release
```

If `cargo build` reports "Finished release [optimized] target(s)"
with files compiled (not just "Finished in 0.x s" with nothing
recompiled), great. If it skipped recompile and you suspect the
binary is stale, force it: `cargo build --release --force` (or just
delete `target/release/ironclaw` first).

### 8. IronClaw running with substrate-session enabled

```sh
pkill -f ironclaw
~/projects/ironclaw/target/release/ironclaw
```

Watch the boot output for this line (it confirms the new auth path
is loaded, not just compiled in):

```
INFO Substrate-session cookie auth enabled cookie_name=zp_session
```

The boot summary card may still say `auth: OIDC + bearer` — that's a
cosmetic display gap and does NOT mean the new path is off. The
INFO line is the real signal.

If the INFO line doesn't appear, the env vars from step 6 aren't
being read. Re-check the `.env` location, line formatting, and
whether IronClaw was launched from a context that picks up your
shell env.

---

## Director's environment

### 9. Operator row has placeholder public key

```sh
cd ~/projects/zeropoint/zeropointfoundation.org
npx wrangler d1 execute zpmail --remote \
  --command="SELECT id, name, role, substr(public_key_hex, 1, 16) AS key_prefix FROM operators WHERE id = '<director_id>';"
```

The `key_prefix` column should be all zeros (`0000000000000000`). If
it shows real-looking key bytes, the director was already partially
onboarded — reset with:

```sh
npx wrangler d1 execute zpmail --remote \
  --command="UPDATE operators SET public_key_hex='0000000000000000000000000000000000000000000000000000000000000000' WHERE id='<director_id>';"
```

This is destructive but appropriate for re-onboarding. The audit
chain still has receipts from any prior attempt — those persist as
historical record.

### 10. Director is on a fresh browser session

The director should open a new private/incognito window before
visiting `zeropointfoundation.org/onboard/`. Reasons:

- Any prior CF Access JWT cookies under `*.cloudflareaccess.com`
  could let them through `app.zp.org` via the OLD path even if CF
  Access is removed — that would obscure whether the substrate
  session actually worked.
- A clean session removes any cached state from prior failed
  attempts.

---

## Pre-pilot smoke test

If all 10 boxes pass, run one end-to-end smoke test BEFORE the
director arrives:

```sh
# In a private window, visit the wizard:
open -na "Comet" --args --incognito "https://zeropointfoundation.org/onboard/"
```

Pick a *non-director* operator (or temporarily insert a `test`
operator) and walk through. The wizard should:

1. Show 5 director options at Phase 1
2. Generate keypair at Phase 2, display a fingerprint
3. Register the operator at Phase 3
4. Show recovery phrase at Phase 4
5. Offer passkey (skippable) at Phase 5
6. Show 7 voice cards at Phase 5.5
7. Run capability self-test at Phase 6
8. Show handoff card at Phase 7

Click "Go to my workspace →" — you should land in IronClaw at
`app.zp.org` with the chat interface, no email-OTP, no token paste.

If the smoke test passes, reset the test operator's row and you're
ready for the real director.

---

## During the pilot

Don't try to fix bugs mid-pilot. If something breaks, log it (the
audit chain captures what actually happened, and the chat
transcript gives the rest) and finish or abort the session
gracefully. Triage and fix after.

Known bug surface as of 2026-05-13 (see tasks #140, #141, etc.):

- Clicking a voice's ▶ Sample button does not also select that voice;
  director must click the card itself (NOT just the play button) to
  make their selection stick
- Voice samples may not play in private/incognito windows on some
  browsers (Comet observed); browser will appear silent with no
  diagnostic
- Wizard's "already onboarded" branch is a dead-end with no path
  forward to the workspace
- Phase 7 narration mentions "Six receipts" hardcoded; actual count
  varies

Tell the director about these before they start; manage expectations.

---

## After the pilot

- Director's operator row now holds their real public key — DO NOT
  reset without explicit cause
- Audit-chain receipts from the ceremony are the formal record of
  their joining
- New bugs surfaced during the run: file as tasks against the
  appropriate component (wizard, IronClaw, deploy infra)
- The 24-word recovery phrase the director wrote down is the ONLY
  way back in if their device is lost; emphasize that aftercare

---

## References

- `docs/STEWARD-WIZARD-SCRIPT-2026-05.md` (file was renamed to
  SAGE-WIZARD-SCRIPT-2026-05.md mid-arc; same content) — the
  ceremony's interaction script
- `docs/AGENT-AS-UX-ARCHITECTURE-2026-05.md` — Sage voice and
  framing patterns
- `docs/handoffs/ironclaw-substrate-session-auth-2026-05.md` — the
  substrate-session auth brief
- CLAUDE.md → "Workflow heuristics" → *For systems spanning trust
  boundaries, only production tests production* — the meta-lesson
  this checklist exists to honor
