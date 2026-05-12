# Welcome — Ken

*Executive Director, ZeroPoint Foundation. Genesis holder.*

You already know what this is. This packet exists so the chain of onboarding
documents is complete and identical in shape across the board.

## Your role

Executive director. Genesis holder. The root of the trust substrate this
foundation runs on. Every other director's authority traces to a delegation
from yours.

## Your capabilities (as written in D1)

```
mail:*           — read, send, manage any mailbox
docs:*           — read and write any document
media:*          — full media access
tasks:*          — full task access
operators:read   — see the operator registry
receipts:read    — read the audit chain
admin:*          — administrative actions
```

You have per-domain wildcards rather than `workspace:admin`. The capability
checker (`src/auth/capabilities.js`) currently short-circuits on
`workspace:admin` only. Your wildcards still match the actions you take, but
any code path that explicitly tests `workspace:admin === true` will reject
you. See `STAFF-ONBOARDING.md` §2 for the resolution.

## Operating notes

- Steps 3 and 4 of the runbook are yours to execute for the other four
  directors. Until each has a real public key in D1 and a delivered welcome
  packet, the foundation is operating on placeholder identities.
- The `succession:invoke` capability isn't held by anyone in the current seed.
  Decide before any binding receipt is signed: paper succession plan, or
  designated successor in D1 with the cap.
- Production sovereignty isn't on yet. Touch ID Secure Enclave or Trezor
  required before any director signature represents a binding decision. See
  `PRODUCTION-GENESIS-CHECKLIST.md`.

## Next steps for you

You're already through Steps 1–5 in spirit. Open items:

1. Resolve the `workspace:admin` vs `admin:*` discrepancy — migration or
   capability-checker change.
2. Generate real keypairs for the other four directors (or get them to do it),
   replace placeholders, deliver packets.
3. Decide the succession question.
4. Schedule production sovereignty cutover.
