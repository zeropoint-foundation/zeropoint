# Foundation Worker as Edge Proxy — Receipt Forwarding to Operator zp-server

*Dated 2026-05-26.*

---

## Why this exists

The Foundation worker's earlier shape was "sign foundation-worker receipts
in place on Cloudflare D1." That codified the wrong architecture. The
chain shouldn't live on D1:

- **P3 (no center).** D1 is Cloudflare's centrally-operated storage.
  Putting the chain there makes Cloudflare a single point of trust failure
  that isn't the operator.
- **Portability thesis.** "Portable trust for the Agentic Age." An
  operator must be able to take their chain with them. A D1-resident
  chain can't be exported as a portable artifact without re-engineering.
- **P5 (store-and-forward is primary).** The chain must survive
  Cloudflare going down. Only true if the chain lives on operator-controlled
  infrastructure.

The architecture: Foundation worker is a **thin edge proxy with no chain**.
Operator's `zp-server` is the canonical chain holder and signer. Worker
forwards receipt-intents synchronously; operator's `zp-server` signs and
writes to `~/ZeroPoint/data/audit.db` and returns the signed receipt. The
worker has no signing key for receipts.

Each operator's existing chain absorbs Foundation actions on their behalf.
The operator's existing signing primitives — derived from Genesis under
the singular-sovereign-root principle — sign every receipt, with no
edge-stored receipt-signing key material at all.

## The architecture

```
                    Operator (e.g. APOLLO)
                    ┌─────────────────────────────────┐
                    │  zp-server                      │
                    │  - audit.db (canonical chain)   │
                    │  - signing keys (Genesis-       │
                    │    derived)                     │
                    │  - POST /v1/foundation-receipts │
                    │  - GET  /v1/foundation-receipts │
                    └────────────────┬────────────────┘
                                     │
                              Cloudflare Tunnel
                                     │
                    ┌────────────────┴────────────────┐
                    │  Foundation Edge                │
                    │  (Cloudflare worker)            │
                    │  - HTTP proxy                   │
                    │  - Ed25519 envelope signing     │
                    │  - operators table (D1)         │
                    │    (pubkey registry, endpoints) │
                    │  - NO chain, NO receipt signing │
                    └────────────────┬────────────────┘
                                     │
                              public requests
                                     │
                              [internet]
```

The worker has its own identity (an Ed25519 keypair, the **Foundation
Edge identity**) used solely to authenticate forwarded intents to the
operator's `zp-server`. That identity is distinct from any
receipt-signing key — different role, different trust scope. The
worker's identity says "this intent came from the legitimate Foundation
edge"; the operator's identity says "this receipt is canonical."

## Endpoint contracts

### POST /v1/foundation-receipts (operator's zp-server)

Worker forwards receipt-intents here. Operator signs and stores.

**Request body** (JSON, the *intent*):

```json
{
  "intent_id": "intn-01HZ...",
  "operator_id": "op-ken",
  "claim": "mail:read",
  "subject": "msg-01HZ...",
  "capability_used": "mail.read",
  "metadata": { "ip": "1.2.3.4", "ua": "..." },
  "requested_at": "2026-05-26T19:30:00Z"
}
```

**Request headers** (Ed25519 envelope auth):

```
X-Foundation-Worker-Pubkey-Id: <hex pubkey, identifies which worker key>
X-Foundation-Worker-Signature: <base64 Ed25519 sig over canonical body bytes>
Content-Type: application/json
```

**Operator's zp-server validation**:

1. Look up `X-Foundation-Worker-Pubkey-Id` in the worker pubkey registry
   (on-host config file; small set, typically one entry).
2. Verify `X-Foundation-Worker-Signature` against canonical body bytes.
3. Validate intent shape against schema.
4. Dedupe on `intent_id` (idempotency).
5. Build canonical receipt:
   - `id`: ULID-prefixed by `receipt_type`
   - `version`: "1.0.0" (matching api/receipt.schema.json)
   - `receipt_type`: "Access"
   - `status`: "Success" (or "Denied" for failure receipts)
   - `trust_grade`: depends on the operator's signing key
   - `content_hash`: Blake3 over canonical-JSON of receipt body
   - `prev_hash`: content_hash of operator's previous chain entry, or
     NULL on first signed receipt
   - `signatures`: F8 algorithm-agile vec — Ed25519 signature using the
     operator's signing key from the singular-sovereign-root path
   - `executor.id`: derived from operator + edge worker pubkey
6. Append to `audit.db` chain.
7. Return signed receipt JSON.

**Response** (signed receipt, conforming to api/receipt.schema.json):

```json
{
  "id": "accs-01HZ...",
  "version": "1.0.0",
  "receipt_type": "Access",
  "status": "Success",
  "content_hash": "<64 hex>",
  "trust_grade": "B",
  "created_at": "2026-05-26T19:30:00Z",
  "prev_hash": "<64 hex or null>",
  "executor": { ... },
  "action": { ... },
  "signatures": [ { "algorithm": "Ed25519", "key_id": "...", "signature": "..." } ]
}
```

### GET /v1/foundation-receipts (operator's zp-server)

Worker proxies read requests here. Operator returns chain query results.

**Query params**:
- `operator_id` (required) — which operator's chain to query
- `limit` (default 50, max 500)
- `cursor` (optional) — opaque pagination token
- `after` (optional ISO timestamp)
- `before` (optional ISO timestamp)
- `claim` (optional, filter)

Same envelope auth headers as POST. Returns paginated list of signed
receipts matching the filter.

## Worker-side

### `zeropoint.global/src/auth/forward.js`

Edge-signing client. Knows:
- The Foundation Edge signing key (from `FOUNDATION_EDGE_SIGNING_KEY` env)
- Operator endpoint URL lookup (from D1.operators table)

```js
export async function forwardReceipt(env, operatorId, intent) {
  const endpoint = await lookupOperatorEndpoint(env, operatorId);
  const bodyBytes = canonicalBytes(intent);
  const sig = await edSign(env.FOUNDATION_EDGE_SIGNING_KEY, bodyBytes);
  const res = await fetch(`${endpoint}/v1/foundation-receipts`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Foundation-Worker-Pubkey-Id": env.FOUNDATION_EDGE_PUBKEY_ID,
      "X-Foundation-Worker-Signature": sig,
    },
    body: bodyBytes,
    signal: AbortSignal.timeout(2000),
  });
  if (!res.ok) throw new ForwardError(res.status, await res.text());
  return await res.json();
}

export async function fetchReceipts(env, operatorId, query) { ... }
```

Uses `@noble/ed25519` (small, audited, runs in Cloudflare Workers).
Canonical bytes via a minimal canonical-JSON helper (sorted keys, no
whitespace).

### `zeropoint.global/src/auth/receipts.js`

`emitReceipt` and `emitAuthFailure` are thin wrappers that:
1. Build the intent payload from opts
2. Call `forwardReceipt(env, opts.operatorId, intent)`
3. Return the signed receipt's `id` (preserving the caller API)

No D1 INSERT. No content_hash computation. No signing. All of that lives
on the operator's `zp-server`. The existing call sites in `worker.js`
don't need to change — the `emitReceipt(env, opts) => receiptId` contract
is preserved.

### `zeropoint.global/src/worker.js` read path

The `/api/receipts` read path is served by `fetchReceipts(env, operatorId,
query)`. Same response shape to callers (JSON list of receipts), sourced
canonically from operator's `zp-server`.

If the operator is offline at read time: return 503. Same honest failure
mode as the write path.

## Operator zp-server

Implements the `/v1/foundation-receipts` POST and GET handlers in the
existing zp-server HTTP router. Validates worker envelope auth, then
composes the receipt using the existing `zp-receipt` crate (F8
algorithm-agile signing, Blake3 canonical hash, prev_hash chain linking
against `audit.db`).

### Worker pubkey registry

On-host config file: `~/ZeroPoint/config/foundation-edge-keys.json` —
maintained by `zp keys derive foundation-edge`.

**Shape:**

```json
{
  "keys": [
    {
      "id": "fwed-2026-05-26-a1b2c3d4",
      "pubkey": "<64 hex chars>",
      "added_at": "2026-05-26T19:30:00.000000Z",
      "rotated_to": null
    }
  ]
}
```

**Field semantics:**

- `id` — stable identifier, format `fwed-YYYY-MM-DD-<8 hex>`. The date
  is the derivation day for human-readable chronological reading; the
  8-hex suffix is the first 8 characters of the derived pubkey, so
  different domain-context versions or different Genesis keys produce
  different IDs even on the same day.
- `pubkey` — full 64-hex Ed25519 public key bytes. Used to verify the
  envelope signature against the request body.
- `added_at` — RFC3339 UTC timestamp when this entry was registered or
  last refreshed.
- `rotated_to` — null while active; tag pointing at the successor key's
  `id` when this key is rotated out. Allows a transition window where
  both old and new keys are accepted, with the rotation lineage recorded
  in-place.

**Active set:** any entry with `rotated_to == null` is currently valid.
Operator's `zp-server` accepts envelopes signed by any pubkey matching
one of those entries.

**Persistence:** written via `zp_keys::write_secret_file` (atomic,
restrictive perms). Manual editing is supported — the format is stable
and the operator can delete entries directly to immediately revoke a
worker's pubkey.

### audit.db schema

No changes from this work. Foundation-relayed receipts go in the same
chain as any other operator action. `executor.id` distinguishes them
from receipts originating on the operator's own host.

## D1 changes

```sql
ALTER TABLE operators ADD COLUMN zp_server_endpoint TEXT;
```

Stores the operator's `zp-server` public endpoint (the Cloudflare Tunnel
URL terminating at the operator host). NULL means "not yet configured" —
those operators can't have Foundation actions relayed.

The `receipts` table is not written to by the new path. Existing rows
remain as historical artifacts from the prior architecture.

## Auth — Ed25519 envelope signatures

Foundation Edge holds its own Ed25519 keypair, used to sign forwarded
request bodies. Not a receipt-signing key — different role, different
trust scope.

**Key material lifecycle**:

1. Generate on a Genesis-bearing host via `zp keys derive foundation-edge`
   — derives an Ed25519 keypair from Genesis under the
   singular-sovereign-root principle, outputs the private key (base64)
   and pubkey (hex) plus a stable pubkey_id.
2. `wrangler secret put FOUNDATION_EDGE_SIGNING_KEY` on the worker.
3. `wrangler secret put FOUNDATION_EDGE_PUBKEY_ID` on the worker.
4. The pubkey + id are registered in
   `~/ZeroPoint/config/foundation-edge-keys.json` on the operator host
   so the operator's `zp-server` recognizes it.

**Replay protection**: every intent body includes `intent_id` (ULID) and
`requested_at`. Operator deduplicates by `intent_id` for ~24 hours;
rejects intents whose `requested_at` is more than ±5 minutes from
operator clock.

**Why not HMAC**: HMAC conflates two distinct trust roles
(worker-as-actor and operator-as-chain-holder) into one shared secret.
Ed25519 keeps them asymmetric and composes cleanly with the broader
principle that identity is a key, not a location.

## Network — Cloudflare Tunnel from the operator host

The operator host doesn't need to expose a public port. Cloudflare
Tunnel handles ingress.

**Setup**:

1. `cloudflared tunnel create foundation-relay` (one-time)
2. Tunnel config routes a stable hostname (e.g.
   `relay.zeropointfoundation.org`) to the operator host's local
   zp-server port.
3. The operator endpoint URL stored in D1.operators is that public
   hostname.
4. Worker's `forwardReceipt` fetches from `https://relay.../v1/...`

## Failure modes

| Failure | Worker response | Notes |
|---|---|---|
| Operator zp-server offline | 503 to caller | Honest. No chain entry. Caller can retry. |
| Operator endpoint times out (>2s) | 504 to caller | Same; observability log emitted. |
| Envelope auth fails | 502 to caller + alert | Means worker credential is wrong; needs investigation. |
| Operator returns 4xx (validation) | 502 to caller | Should be rare; means worker is constructing bad intents. |
| Operator returns 5xx (internal) | 502 to caller | Pass-through. |
| Tunnel itself down | 502 (timeout) | Cloudflare-side issue; rare. |

The honesty rule: if there is no canonical place to record a receipt,
the action does not happen. Caller gets an error, not a fabrication.

## Deployment ceremony

```bash
# On the operator host:
$ zp keys derive foundation-edge
# Outputs: pubkey_id, pubkey (hex), private_key (base64)
# Registers the pubkey in ~/ZeroPoint/config/foundation-edge-keys.json

# Set up Cloudflare Tunnel pointing to the operator host's zp-server:
$ cloudflared tunnel create foundation-relay
$ cloudflared tunnel route dns foundation-relay relay.zeropointfoundation.org
# Configure ~/.cloudflared/config.yml to route the tunnel to zp-server's port

# In zeropoint.global/:
$ wrangler secret put FOUNDATION_EDGE_SIGNING_KEY   # paste the base64 private key
$ wrangler secret put FOUNDATION_EDGE_PUBKEY_ID     # paste the pubkey_id

# Register the operator endpoint in D1:
$ wrangler d1 execute zpmail --remote --command \
  "UPDATE operators SET zp_server_endpoint='https://relay.zeropointfoundation.org' WHERE id='<operator-id>'"

# Apply the operators-table migration:
$ wrangler d1 execute zpmail --remote --file=migrations/0006_operator_endpoint.sql
```

## Refs

- `docs/SIGNATURES-2026-05.md` — F8 algorithm-agile signature surface
- `docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md` — operator key derivation
- `docs/ARTIFACT-LIBRARY-2026-05.md` — adjacent receipt-flow primitives
- `docs/ARCHITECTURE-2026-04.md` Part V½ — design principles cited
- `zeropoint.global/api/receipt.schema.json` — canonical receipt shape
- `crates/zp-receipt/src/signer.rs` — operator-side signing primitives
- `crates/zp-keys/src/foundation_edge_signer.rs` — derivation primitive
