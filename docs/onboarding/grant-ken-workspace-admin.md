# Grant Ken `workspace:admin` (one-shot)

The seed seeded Ken with per-domain wildcards (`mail:*`, `docs:*`, etc.) plus
`admin:*`. None of those satisfy a `workspace:admin` check — verified live:
`GET /api/receipts` returned `403 + {"required":"workspace:admin"}`. This
unblocks the executive-director endpoints (operator registration, audit
trail read, doc/media delete, media publish).

## Run on APOLLO from `zeropoint.global/`

```sh
npx wrangler d1 execute zpmail --remote --command "UPDATE operators SET capabilities = '[\"mail:*\",\"docs:*\",\"media:*\",\"tasks:*\",\"operators:read\",\"receipts:read\",\"admin:*\",\"workspace:admin\"]' WHERE id = 'ken';"
```

`zpmail` is the binding name (`env.DB` → D1 Database `zpmail` per the deploy
output). `--remote` targets production; drop it if you want to apply locally
first.

## Verify

```sh
npx wrangler d1 execute zpmail --remote --command "SELECT id, capabilities FROM operators WHERE id = 'ken';"
```

The capabilities cell should end in `…,"workspace:admin"]`.

Then exercise it from any machine:

```sh
TOKEN=$(curl -sS -X POST -H 'Content-Type: application/json' -d '{"operatorId":"ken"}' \
  https://zeropointfoundation.org/api/auth/session | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")

curl -sS -H "Authorization: Bearer $TOKEN" \
  https://zeropointfoundation.org/api/receipts | head -c 300
```

Should return 200 with the receipts payload, not the 403 it returns today.

## Why the additive form

Keeping the per-domain wildcards in place means anything that explicitly
inspects Ken's grants (audit display, future tooling that lists what an
operator can do) still sees the granular trail. `workspace:admin` is the
short-circuit; the rest is the explicit log of why he should pass each gate.

Note: the session token caches the capabilities at issue time. After
running the UPDATE, throw away any token created before it and POST a fresh
session — the new token will carry the updated cap set.
