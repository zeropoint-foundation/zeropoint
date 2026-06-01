# Foundation Worker Chain Relocation — Chains Live With Their Sovereign

*Dated 2026-06-01. Architectural correction surfaced by the first empirical*
*end-to-end test through the foundation worker. Supersedes the partial*
*implementation captured in foundation-worker-edge-proxy-2026-05.md, which*
*targeted only the `zeropoint-global` worker and did not yet account for*
*the `zeropoint-foundation` worker's existing edge-signed chain.*

---

## The principle

There can be multiple chains. **Every chain must live with the sovereign
whose actions it attests to.** The thesis is not "one chain"; it is "no
center." Edge-storage of any chain — on Cloudflare D1, on a CDN, on any
infrastructure not controlled by the sovereign — places a centerpiece in
the trust path for whatever actions that chain attests to. That violates
P3 (there is no center), regardless of how cleanly the chain is signed
on its way in.

The test is *who hosts each chain*, not *how many chains exist*. A chain
hosted by its sovereign honors P3. The same chain mirrored to edge storage
does not. The number of chains is a property of how many distinct
sovereigns are acting; the location of each chain is a property of which
sovereign owns it.

## Current misalignment

The `zeropoint-foundation` worker (`zeropointfoundation.org/src/auth/receipts.js`)
runs a **foundation-canonical-v1** signing path that is structurally
sophisticated but architecturally misplaced:

- Ed25519 signing via WebCrypto with a foundation edge key
  (`FOUNDATION_SIGNING_KEY_PKCS8_B64`)
- Hash-linked chain in a separate D1 table, `chain_entries`, with sequence
  numbers, prev_hash linking, canonical hashing
- Sign-on-emit semantics
- A legacy fallback path that inserts into the older `receipts` table when
  no signing key is configured

The code is well-built. It is also located on Cloudflare's edge. When the
foundation worker uses it to sign a receipt for "Ken read his mail," the
canonical record of an action attributable to Ken lives on Cloudflare's
infrastructure. The operator's own audit chain at `~/ZeroPoint/data/audit.db`
has no record of the action — the substrate that should be the canonical
authority for Ken's actions is bypassed.

That is the misalignment. It is the same shape of misalignment the
preceding handoff doc identified for D1's `receipts` table; it was simply
not yet visible because the design pass had only inspected the
`zeropoint-global` worker.

## The corrected architecture

The foundation worker becomes a thin edge proxy with **no chain at all**.
Every receipt-emitting path forwards a receipt-intent to the relevant
sovereign's `zp-server`, which signs the canonical receipt against its own
audit chain and returns the signed receipt to the worker. The wire shape
is the one already designed for the `zeropoint-global` worker's Cut C
forwarding (envelope-signed POST, operator pubkey registry, Ed25519
envelope auth): the foundation worker reuses that same forwarding
primitive.

For operator-attributable actions — Ken reading his mail, Carlie listing
her docs, any action whose semantic actor is a workspace operator —
the foundation worker forwards to *that operator's* `zp-server`. The
receipt lands on that operator's `audit.db`. Cloudflare is removed from
the trust path entirely.

For Foundation-institutional actions — the Foundation entity itself doing
something, distinct from any individual operator acting through it — the
forwarding target is the Foundation's `zp-server`. *Today*, that
infrastructure does not exist separately from Ken's operator zp-server,
because the Foundation does not yet have a distinct sovereign identity
provisioned (its own Genesis, its own host, its own signing keys). In the
near term, Ken's `zp-server` serves as the Foundation's actor-of-record
by transitive identity — Ken is currently the Foundation's executive
identity, and Foundation actions are attributable to him until the
institution itself is sovereign-provisioned.

When the Foundation matures as a distinct sovereign entity — its own
Genesis ceremony, its own host, its own signing keys — a Foundation
`zp-server` stands up alongside operator `zp-server`s, and the foundation
worker's forwarding routes by actor: operator-attributable to operator's
host, Foundation-institutional to Foundation's host. The mature shape is
multi-chain, multi-sovereign, all off-edge.

## The transitional path

The arc has three states:

**State 0 (current):** Foundation worker signs locally on edge. Chain
lives in Cloudflare D1. P3 violated for every action it attests. Operator's
audit chain has no record of foundation-worker-mediated actions.

**State 1 (near-term, this refactor):** Foundation worker is a thin
proxy. Every receipt-intent forwards to operator's `zp-server` for
canonical signing. One chain (operator's audit.db) holds the record of
all actions, including Foundation-institutional ones. P3 honored
uniformly. The Foundation's institutional actions are attributable to
the operator by transitive identity.

**State 2 (future, when Foundation sovereignty stands up):** Foundation
worker is still a thin proxy. Forwarding target depends on the action's
actor — operator-attributable to operator's zp-server, Foundation-
institutional to Foundation's own zp-server. Two chains, both sovereign-
hosted, both honoring P3. The foundation-canonical-v1 code may migrate
into the Foundation's zp-server, where its hash-linked-Ed25519 signing
shape becomes architecturally appropriate.

State 1 is achievable now. State 2 is gated on the Foundation acquiring
its own sovereign infrastructure, which is a separate arc (Genesis
ceremony for the Foundation entity, host provisioning, key derivation).

## Refactor scope (State 0 → State 1)

The `zeropoint-foundation` worker changes:

- **`src/auth/receipts.js`** — replace `_signedEmitReceipt` and
  `_legacyEmitReceipt` with a single forwarding path. `emitReceipt` and
  `emitAuthFailure` become thin wrappers that construct a receipt-intent
  and call `forwardReceipt(env, operatorId, intent)`. The
  caller signature is preserved so worker.js call sites are untouched.
- **`src/auth/forward.js`** — port from `zeropoint.global/src/auth/forward.js`.
  Same `canonicalJSON`, same Ed25519 envelope signing via `@noble/ed25519`,
  same `lookupOperatorEndpoint` (reads `zp_server_endpoint` from the
  shared `D1.operators` table), same `forwardReceipt` + `fetchReceipts`
  shape.
- **`package.json`** — add `@noble/ed25519` dependency.
- **`src/worker.js`** — receipts read paths (anything currently reading
  `chain_entries` or `receipts` table) become proxied `fetchReceipts`
  calls. The 18+ `emitReceipt` call sites stay untouched in shape; their
  underlying behavior shifts beneath them.
- **`src/chain/*.js`** — `chain.js`, `canonical.js`, `getFoundationKeypair`,
  `writeGenesis`, `readChainTip` and related — these become dead code.
  Either delete or move to `archive/` with a note explaining they were
  the foundation-canonical-v1 code that will migrate to the Foundation's
  own `zp-server` when that sovereign infrastructure stands up.
- **Cloudflare worker secrets** — the foundation worker needs its own
  `FOUNDATION_EDGE_SIGNING_KEY` and `FOUNDATION_EDGE_PUBKEY_ID` (set via
  `wrangler secret put` from `zeropointfoundation.org/`). The same operator-
  pubkey-registry consumer pattern as the `zeropoint-global` worker.

## D1 chain_entries — historical artifact disposition

The `chain_entries` table on D1 contains real entries: actual workspace
actions that landed there during State 0. They have value as historical
record, but they are not part of the operator's canonical chain and
should not be retroactively migrated *into* it (that would be a
cryptographic lie — those entries were never signed by the operator's
audit signer).

Honest disposition:

- The `chain_entries` table is left in place after the cutover, frozen.
  Existing rows remain as the foundation-canonical-v1-era historical
  record. No new writes after the cutover.
- A cutover marker is documented: the date the forwarding refactor
  deployed. Operators can know that workspace actions before that date
  exist only on the edge chain; actions from that date forward exist on
  their own audit.db.
- When State 2 arrives, the historical `chain_entries` rows may be
  imported into the future Foundation zp-server's chain as
  "pre-relocation historical entries," explicitly distinguished from
  Foundation-attestation entries signed under State 2.

This is the same shape as the abandoned-migration disposition adopted
earlier for `0006_receipt_signing.sql` — preserve history honestly,
don't retroactively forge attestations.

## Open questions

- **Operator pubkey registry on the foundation worker side.** The
  forwarding pattern relies on `D1.operators.zp_server_endpoint`. That
  column is already in the shared `zpmail` D1 (added during the prior
  refactor), so no migration is needed. Confirm during implementation
  that the foundation worker's bindings actually expose the same D1.
- **The `_legacyEmitReceipt` fallback** that writes to the old `receipts`
  table — does anything currently depend on that table's existence? If
  yes, the cutover needs to preserve at least read access; if no, the
  table can be sunset alongside `chain_entries`.
- **Read-path migration.** The foundation worker likely has UI surfaces
  that query `chain_entries` for display. Those queries need to redirect
  to `fetchReceipts` against the operator's `zp-server` for current data,
  with a clear separation between "pre-cutover historical view" (D1) and
  "current canonical view" (operator chain).
- **Foundation Genesis ceremony.** Designing the Foundation's eventual
  sovereign provisioning is its own arc, not part of this refactor.
  Worth flagging that the corrected architecture *anticipates* it
  without requiring it; State 1 is fully functional with a single
  operator chain serving as the Foundation's actor-of-record.

## Why this surfaced now

The empirical loop produced disproportionate value here. The first
end-to-end success-path test was being designed to exercise Cut C's
forwarding through the foundation worker. Loading the foundation worker's
actual receipts.js revealed it was running an entirely different
architecture (foundation-canonical-v1, edge-signed in D1), which the
prior design pass had not inspected. The misalignment between committed
principle (P3) and deployed code was not visible until the loop attempted
to operate through it.

This is exactly the discovery pattern the balanced-loop discipline
predicts: small functional test exposes a real structural gap, and
fixing the gap is more architecturally consequential than the test
itself. The thesis-aligned refactor is now visible because we tried to
do one small thing through the worker.

## Refs

- `docs/handoffs/foundation-worker-edge-proxy-2026-05.md` — prior design
  pass; covered `zeropoint-global` only
- `docs/ARCHITECTURE-2026-04.md` Part V½ Principle 3 (there is no center)
  — the principle this refactor restores
- `docs/SIGNATURES-2026-05.md` — F8 algorithm-agile signature surface;
  operator's audit signer derives from Genesis per singular-sovereign-root
- `zeropointfoundation.org/src/auth/receipts.js` — current
  foundation-canonical-v1 implementation
- `zeropointfoundation.org/src/chain/*.js` — the edge-chain primitives
  that become dead code or relocate
- `zeropoint.global/src/auth/forward.js` — reference implementation of the
  forwarding primitive being ported
- `crates/zp-server/src/foundation_relay.rs` — operator-side endpoint that
  consumes the forwarded intents
