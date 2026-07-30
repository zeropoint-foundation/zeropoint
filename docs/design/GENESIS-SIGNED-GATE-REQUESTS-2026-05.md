> **Promoted from `docs/handoffs/` on 2026-07-29.** Shipped code cites this document
> as its rationale — `crates/zp-server/src/auth.rs:594` — and `docs/handoffs/` is excluded by `.gitignore`, so the
> code travelled with the repo and the reason for it did not. Promotion test: a handoff
> moves when something shipped cites it. Content unchanged; the handoff original remains
> in place locally. References below to companion *investigation* documents still point
> into `docs/handoffs/` and are still local-only.

**Document type:** Design record, 2026-05-16. **Status:** the ZP half is implemented in `crates/zp-server/src/auth.rs`, which cites this document. **Paths as proposed** — file paths below are the May-2026 plan, not the current tree, and sixteen of them no longer resolve. Most name the IronClaw side (`src/zp/client.rs`, `src/zp/hook.rs`, `crates/ironclaw/`), and IronClaw was removed from the stack on 2026-07-27; that half of this design is retired and will not be built. One more, `crates/zp-discipline/tests/no_inline_gate_signer_derivation.rs`, is a pin this document proposed and nobody landed — still open, and now visible in `DISCIPLINE-PINS-MAP.md` terms as a promised-not-landed rule.

# Design — Genesis-signed gate requests

*2026-05-16. Design deliverable for the brief
`docs/handoffs/genesis-signed-gate-requests-investigation-2026-05.md`. Replaces the
producer-consumer bearer-token model (`ZP_SESSION_TOKEN` +
`~/ZeroPoint/session.json`) with per-request Genesis-signed envelopes.
Closes #167 and #168 by removing the state they were trying to keep
synchronized. Composes with #152 (singular sovereign root).*

> **Scope note.** This is a spec, not an implementation. No code lands in
> this round. The deliverable is the envelope format, the signer
> derivation, the gate verification middleware shape, the IronClaw caller
> shape, the migration sequence, the edge-case treatment, the acceptance
> tests, the discipline-pin candidate, and the cleanup checklist.

---

## 1. Current state map

Exact file/line citations for every site the new path supersedes. (One
correction to the investigation brief: the `max_age_secs` constant lives
in `crates/zp-server/src/auth.rs:129`, not `crates/zp-keys/src/auth.rs`.
The brief's citation pre-dates the auth module's move into `zp-server`.)

### 1.1 Token issuance (`zp serve` → `~/ZeroPoint/session.json`)

| File | Lines | What |
|------|-------|------|
| `crates/zp-server/src/auth.rs` | 119–170 | `SessionAuth::new_with_persistence` — mints HMAC key from signing-key bytes (SHA-256, domain tag `b"zp-session-v1"`), reads or mints token, writes session.json |
| `crates/zp-server/src/auth.rs` | 126–129 | `max_age_secs = 8 * 60 * 60` (overridable via `ZP_SESSION_MAX_AGE_SECONDS`) |
| `crates/zp-server/src/auth.rs` | 173–181 | `mint_token` — SHA-256(hmac_key ‖ nonce ‖ timestamp_le), hex-encoded |
| `crates/zp-server/src/auth.rs` | 42–56 | `PersistedSession` struct: `{token, created_at, key_fp, version}` |
| `crates/zp-server/src/auth.rs` | 197–212 | `SessionAuth::rotate` — mints fresh token, updates `created_at`, rewrites disk |
| `crates/zp-server/src/auth.rs` | 252–254 | `session_file_path()` → `zp_paths::session_path()` |
| `crates/zp-server/src/auth.rs` | 309–349 | `persist_session` — atomic write (tmp + rename, 0600 on Unix) |

### 1.2 Token validation (gate middleware)

| File | Lines | What |
|------|-------|------|
| `crates/zp-server/src/auth.rs` | 218–236 | `SessionAuth::verify` — TTL check then constant-time bytes compare |
| `crates/zp-server/src/auth.rs` | 564–575 | `extract_cookie_token` — parses `Cookie: zp_session=…` |
| `crates/zp-server/src/auth.rs` | 588–712 | `require_auth` middleware — Bearer / Cookie / `?token=` (WS-only) extraction, 401 with `X-Auth-Reason: missing\|stale`, rate-limiter integration |
| `crates/zp-server/src/auth.rs` | 718–733 | `build_auth_response` — JSON body for 401 |
| `crates/zp-server/src/lib.rs` | ~1116–1125 | Middleware wiring via `axum::middleware::from_fn` |

### 1.3 Token injection into IronClaw (`zp configure exec`)

| File | Lines | What |
|------|-------|------|
| `crates/zp-cli/src/main.rs` | 1493–1509 | Reads `read_zp_session_token()`, injects `ZP_SESSION_TOKEN` into child env. Non-fatal: warns if session.json missing |
| `crates/zp-cli/src/main.rs` | 3992–4017 | `read_zp_session_token` + `read_zp_session_token_from` — JSON parse, `.token` field |

### 1.4 IronClaw side (consumer)

| File | Lines | What |
|------|-------|------|
| `src/zp/config.rs` | 36–46 | `ZpConfig::from_env` — gated by `IRONCLAW_ZP_ENABLED=true`, reads `ZP_SESSION_TOKEN` into `SecretString` |
| `src/zp/config.rs` | 8–9 | `DEFAULT_ZP_BASE_URL = "http://localhost:17010"` |
| `src/zp/client.rs` | 56–79 | `ZpClient` struct + `::new` — stores `bearer: "Bearer <token>"` formatted **once** at construction |
| `src/zp/client.rs` | 83–122 | `gate_tool_call` → `POST /api/v1/gate/tool-call` with `authorization` header |
| `src/zp/client.rs` | 127–164 | `observe` → `POST /api/v1/cognition/observe` with `authorization` header |
| `src/zp/hook.rs` | 182–192 | On 401/403 in `BeforeToolCall`: log, `self.disable()`, reject with "Re-onboard or refresh ZP_SESSION_TOKEN, then retry" |
| `src/zp/hook.rs` | 246–252 | On 401/403 in `TransformResponse`: log, disable, allow turn |
| `src/app.rs` | 1171–1196 | `AppBuilder::build_all` — where `ZpConfig::from_env` then `ZpClient::new` then hook registration happens. **This is where the new signer loads.** |

### 1.5 Related drift family (cookie / HMAC) — out of scope here

The same pattern also affects the foundation-worker-minted `zp_session`
cookie (production tier, HMAC-keyed). Same shape, different identity
bootstrap — browsers don't have Genesis-derived keys at hand. Closed by
task #139 (substrate-as-sovereign-IdP), not this design. Noted so the
boundary is explicit.

---

## 2. Envelope spec

### 2.1 Header format

Every IronClaw → gate request carries exactly one `Authorization` header
of the form:

```
Authorization: ZP-Sig v=1, kid=<hex_pubkey>, ts=<unix_seconds>, nonce=<base64url_16B>, sig=<base64url_64B>
```

Whitespace after each comma is significant for parser predictability:
exactly `, ` (comma + space). Field order is fixed:
`v, kid, ts, nonce, sig`. Out-of-order or missing fields → 401.

| Field | Format | Length | Notes |
|-------|--------|--------|-------|
| `v` | decimal | 1 | scheme version; only `1` accepted today |
| `kid` | lowercase hex | 64 chars | Ed25519 verifying key (pubkey) for the signer that produced `sig` |
| `ts` | decimal | 10–11 | unix seconds since epoch |
| `nonce` | base64url, no padding | 22 chars | 16 random bytes; uniqueness within the drift window |
| `sig` | base64url, no padding | 86 chars | 64-byte Ed25519 signature over §2.3 canonical bytes |

Total header length: ~250 bytes. Within standard HTTP header limits.

### 2.2 Why `ZP-Sig` and not `Signature:` / `DPoP:` / HTTP Message Signatures?

RFC 9421 HTTP Message Signatures is the convention-correct answer.
Rejected for v1 because:

- The substrate's canonical-bytes form is already defined
  (`zp-receipt::canonical`, "ZP-canonical-v1"). RFC 9421's signature
  base derivation is a parallel canonicalization with different rules
  (header re-serialization, derived components, parameter ordering).
  Adopting it means maintaining two canonical forms in the workspace,
  which violates "every bit counts."
- The substrate's verify primitive (`zp-receipt::verify_signature`) is
  the only sanctioned Ed25519 verify path. RFC 9421's verifier surfaces
  invite implementations that re-roll their own verify — a Seam 5
  violation by construction.
- The pairing with `kid` as a 64-char hex pubkey trivially round-trips
  through the existing `SignatureBlock.key_id` discipline
  (`crates/zp-receipt/src/types.rs:381–433`). RFC 9421 prefers keyid
  references resolved out-of-band, which adds a discovery surface this
  design does not need.

A future v2 may adopt RFC 9421 once those gaps close. The header name
`ZP-Sig` and the `v=` field are designed to coexist: a v2 envelope can
ship as `Authorization: ZP-Sig v=2, ...` without breaking v1 parsers
(unknown `v` → 401, never silent fallback).

### 2.3 Canonical bytes (the message signed)

The signature is computed over the canonical JSON of an `EnvelopeClaims`
object:

```rust
// Lives in: crates/zp-gate-envelope/src/lib.rs  (new crate, see §3.2)

#[derive(serde::Serialize, serde::Deserialize)]
struct EnvelopeClaims {
    /// Scheme version. Must equal `1` for v1 envelopes.
    v: u8,
    /// HTTP method, uppercase ASCII ("GET", "POST", ...).
    method: String,
    /// Request URI path including any query string, leading "/".
    /// Excludes scheme/host/port so the same envelope verifies regardless
    /// of how the gate is fronted (direct, behind cloudflared, etc.).
    path: String,
    /// BLAKE3 hash (hex, 64 chars) of the raw request body bytes.
    /// Empty body → hash of empty input. Never the hex of the JSON
    /// canonical form — always the wire bytes the consumer sees.
    body_hash: String,
    /// Unix seconds since epoch at signing time.
    ts: i64,
    /// Base64url-no-pad of the 16-byte nonce.
    nonce: String,
}
```

Preimage:

```text
canonical_preimage = canonical_bytes_of(&EnvelopeClaims { ... })
preimage_hash      = blake3(canonical_preimage)           // 32 bytes
sig                = ed25519_sign(gate_signing_key, preimage_hash)
```

`canonical_bytes_of` is
`zp_receipt::canonical::canonical_bytes_of`
(`crates/zp-receipt/src/canonical.rs:98`). The same BLAKE3-then-Ed25519
chain `zp-receipt`'s `Signable` trait uses. No parallel canonicalization
pipeline.

The struct implements `zp_receipt::Signable` so verify goes through
`zp_receipt::verify_signed` (the Seam 5 / Seam 20 entry point at
`crates/zp-receipt/src/verify.rs:104`). The `kid` from the header
becomes the `public_key` argument; the parsed `sig` becomes the
`signature` argument.

### 2.4 Why method + path + body_hash + ts + nonce, not more?

Each field is load-bearing:

- **method, path** — bind the signature to the operation so a captured
  envelope can't be replayed against a different endpoint.
- **body_hash** — binds the signature to the payload. Without it,
  an attacker who captured a tool-call envelope could substitute a
  different tool-call body.
- **ts** — drift window enforcement (§7).
- **nonce** — replay protection within the drift window (§7).

Fields explicitly excluded:

- **host / scheme / port** — the gate's URL may change (cloudflared,
  port migration, direct vs. proxied). Binding to host would force
  per-deployment envelope variants.
- **Other request headers** — none are load-bearing for authorization.
  Binding `Content-Type` invites mismatches between IronClaw's
  serialization and what `axum::Json` re-emits.
- **agent name** — IronClaw's `agent_name` field is already in the
  request body (`crates/ironclaw/src/zp/client.rs:95`). It enters the
  preimage via `body_hash`.

---

## 3. Signer derivation

### 3.1 Domain-separated derivation

The gate signer is a Genesis-derived Ed25519 keypair. Derivation mirrors
the audit-signer pattern exactly (`crates/zp-keys/src/audit_signer.rs`):

```rust
// New module: crates/zp-keys/src/gate_signer.rs

/// Context string for gate-request envelope signing. Versioned for
/// future rotation; format mirrors `AUDIT_SIGNER_CONTEXT` /
/// `VAULT_KEY_CONTEXT` (dotted, lowercase, `.vN` suffix).
const GATE_SIGNER_CONTEXT: &[u8] = b"zp.gate.request.v1";

/// Derive the 32-byte gate-request signer seed from Genesis.
///
/// Pure, deterministic, domain-separated. Same Genesis → same seed.
/// Feeds directly into `ed25519_dalek::SigningKey::from_bytes`.
pub fn derive_gate_signer_seed(
    genesis_secret: &[u8; 32],
) -> zeroize::Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_keyed(genesis_secret);
    hasher.update(GATE_SIGNER_CONTEXT);
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(hasher.finalize().as_bytes());
    seed
}
```

This sits alongside:

- `derive_audit_signer_seed` — `b"zp.audit.signer.v1"`
  (`crates/zp-keys/src/audit_signer.rs:52`)
- `derive_vault_key` — `b"zp-credential-vault-v1"`
  (`crates/zp-keys/src/vault_key.rs:42`)

The pattern is established; the new signer is one more domain-separated
subkey under the same shape. No new infrastructure.

### 3.2 Single canonical helper, shared crate

The `EnvelopeClaims` struct, its `Signable` impl, and the header
parser/builder all live in **one new crate**, `zp-gate-envelope`:

```
crates/zp-gate-envelope/
├── Cargo.toml
└── src/
    └── lib.rs
```

Exports:

- `pub struct EnvelopeClaims { ... }` with `Signable` impl
- `pub const HEADER_NAME: &str = "Authorization"`
- `pub const HEADER_SCHEME: &str = "ZP-Sig"`
- `pub fn build_header(claims: &EnvelopeClaims, sig: &[u8; 64]) -> String`
- `pub fn parse_header(value: &str) -> Result<(EnvelopeClaims, [u8; 32] /*kid*/, [u8; 64] /*sig*/), ParseError>`
- `pub fn body_hash_hex(body: &[u8]) -> String`
- `pub fn random_nonce_b64() -> String`

This is the **only** place the envelope format is defined. Both
`zp-server` (verifier) and IronClaw (signer) depend on it. The "both
sides must use the same canonical helper" requirement (a discipline
concern called out in the brief) is structurally enforced by both sides
importing the same crate, plus the discipline pin in §10.

Dependency direction: `zp-gate-envelope` depends on `zp-receipt`
(canonical-bytes, Signable, verify). No back-edges. Keeps the crate
small enough to be obviously correct.

### 3.3 Composition with `load_sovereign_root`

The gate signer is loaded once per process, immediately after Genesis is
loaded:

```rust
// In whatever process needs the gate signer (zp serve, IronClaw, …)

use std::sync::OnceLock;

static GATE_SIGNER: OnceLock<ed25519_dalek::SigningKey> = OnceLock::new();

pub fn gate_signing_key(
    genesis_record_path: &std::path::Path,
) -> Result<&'static ed25519_dalek::SigningKey, KeyError> {
    if let Some(k) = GATE_SIGNER.get() {
        return Ok(k);
    }
    let genesis = zp_keys::sovereignty::load_sovereign_root(genesis_record_path)?;
    let seed = zp_keys::gate_signer::derive_gate_signer_seed(genesis);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    Ok(GATE_SIGNER.get_or_init(|| signing_key))
}
```

`load_sovereign_root`'s actual signature is
`load_sovereign_root(genesis_record_path: &std::path::Path) -> Result<&'static [u8; 32], KeyError>`
(`crates/zp-keys/src/sovereignty/mod.rs:629–653`). It already owns the
process-scoped OnceLock for Genesis itself; this design adds a second
OnceLock specifically for the derived Ed25519 SigningKey so we don't
re-derive on every request.

Properties:

- One ceremony (because `load_sovereign_root` is the single root; #152).
- One OnceLock per signer purpose (mirrors `AuditSigner`'s shape).
- No new credential-store entry — the signer is in-memory only,
  re-derived on every startup. Same property the audit signer has.

The gate's verifier side **derives the pubkey only**, never holds it as
a secret separately:

```rust
// In zp-server gate startup:

let genesis = load_sovereign_root(&genesis_path)?;
let seed = derive_gate_signer_seed(genesis);
let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
let expected_kid: [u8; 32] = vk.to_bytes();
// Store expected_kid in the verifier state.
```

Both sides reach the same `vk` because Genesis + the v1 domain string +
the derivation function is deterministic. The verifier does not need
the secret seed beyond startup — once it has the expected pubkey, every
incoming envelope is verified by reconstructing the preimage and
checking the signature against the pubkey. (This is what enables a
future remote-process variant where the verifier never holds the
signer's secret.)

---

## 4. Gate verification middleware

### 4.1 Insertion point

The `require_auth` middleware in `crates/zp-server/src/auth.rs:588–712`
is the central authentication chokepoint. The new envelope check slots
in as an additional priority above the bearer-token path during
migration, then replaces it after migration:

```text
// New priority order during migration (§6):
//   1. Authorization: ZP-Sig v=1, ...           (envelope path — new)
//   2. Authorization: Bearer <token>            (legacy — kept until migration step 4)
//   3. Cookie: zp_session=<token>               (legacy browser path — scope of #139)
//   4. ?token=<token> on /ws/*                  (legacy WS path — kept until migration done)
//
// Post-migration: only path 1 (plus the browser cookie path for HTML routes).
```

The envelope path bypasses the per-IP failed-auth rate limiter
(`FailedAuthLimiter`). Rationale: rate-limiting is for unauthenticated
brute-force attempts. A request that fails envelope verification at the
structural layer (malformed header, bad signature) is a developer bug
or a deliberate probe, not a credential-guessing attack. The endpoint
rate limiter (`EndpointRateLimiter`) still applies post-auth for cost
control on expensive operations.

### 4.2 Verify shape

```rust
// In zp-server (or extracted to a new helper module):

fn verify_envelope(
    req: &Request,
    body_bytes: &[u8],
    expected_kid: &[u8; 32],
    drift_window: Duration,
    nonce_store: &NonceStore,
) -> Result<(), EnvelopeError> {
    let header = req.headers().get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(EnvelopeError::Missing)?;

    if !header.starts_with("ZP-Sig ") {
        return Err(EnvelopeError::NotEnvelope);  // caller falls through to legacy paths
    }

    let (claims, kid, sig) = zp_gate_envelope::parse_header(header)
        .map_err(EnvelopeError::ParseFailed)?;

    if claims.v != 1 {
        return Err(EnvelopeError::UnknownVersion(claims.v));
    }
    if kid != *expected_kid {
        return Err(EnvelopeError::UnknownSigner);
    }

    // Bind to this specific request:
    if claims.method != req.method().as_str() {
        return Err(EnvelopeError::MethodMismatch);
    }
    let path_and_query = req.uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    if claims.path != path_and_query {
        return Err(EnvelopeError::PathMismatch);
    }
    if claims.body_hash != zp_gate_envelope::body_hash_hex(body_bytes) {
        return Err(EnvelopeError::BodyMismatch);
    }

    // Drift window:
    let now = chrono::Utc::now().timestamp();
    if (now - claims.ts).abs() > drift_window.as_secs() as i64 {
        return Err(EnvelopeError::OutsideDriftWindow);
    }

    // Nonce dedup (replay protection):
    if !nonce_store.try_insert(kid, &claims.nonce, claims.ts) {
        return Err(EnvelopeError::ReplayedNonce);
    }

    // Cryptographic verification — single primitive (Seam 5):
    zp_receipt::verify_signed(&claims, &kid, &sig)
        .map_err(EnvelopeError::SignatureInvalid)?;

    Ok(())
}
```

Body extraction note: `axum::middleware::from_fn` operates on a
`Request`, but the body must be read before the canonical hash can be
computed. The middleware must `let (parts, body) = req.into_parts(); let
body_bytes = axum::body::to_bytes(body, MAX_BODY).await?; let req =
Request::from_parts(parts, Body::from(body_bytes.clone()));` —
buffering the body once, then rebuilding the request for the downstream
handler. `MAX_BODY` should be the existing gate body limit (already
enforced elsewhere; reuse the same constant, do not introduce a
parallel one). The brief's "single middleware point" preference is
satisfied; the body-buffer cost is paid once per request and is
bounded.

### 4.3 Nonce store

```rust
// In zp-server, e.g. crates/zp-server/src/envelope_state.rs

struct NonceStore {
    inner: parking_lot::Mutex<lru::LruCache<([u8; 32], String), i64 /*ts*/>>,
    drift_window: Duration,
}

impl NonceStore {
    fn try_insert(&self, kid: [u8; 32], nonce: &str, ts: i64) -> bool {
        let mut g = self.inner.lock();
        let composite = (kid, nonce.to_string());
        // Age-driven eviction first: clear anything older than drift_window.
        // (LRU handles capacity-driven eviction; quiet periods could
        //  otherwise leave inside-capacity entries past their TTL.)
        let now = chrono::Utc::now().timestamp();
        while let Some((_, entry_ts)) = g.peek_lru() {
            if (now - *entry_ts) <= self.drift_window.as_secs() as i64 { break; }
            g.pop_lru();
        }
        if g.peek(&composite).is_some() { return false; }
        g.put(composite, ts);
        true
    }
}
```

**Capacity sizing.** Reasonable upper bound for a v1 single-tenant
gate: 16 384 entries. At ~50 bytes per entry → ~800 KB resident. Covers
~273 envelopes/sec sustained across the 60-second drift window — orders
of magnitude above current load. Tune via `ZP_GATE_NONCE_CAPACITY` env
var if a future multi-tenant deployment needs more.

**Eviction policy.** Both age-driven (anything older than drift window
is dead) and capacity-driven (LRU). Age-driven runs opportunistically
on each insert; no background task needed.

**Granularity.** Keyed on `(kid, nonce)` — same nonce from different
signers is fine. (Pre-emptively useful for the future multi-signer
case; for v1 there's only one kid so this is just a clean key shape.)

### 4.4 Verifier startup

The gate computes `expected_kid` at startup, after Genesis is loaded:

```rust
// Wherever zp-server constructs its router state:

let genesis = zp_keys::sovereignty::load_sovereign_root(&genesis_path)?;
let gate_seed = zp_keys::gate_signer::derive_gate_signer_seed(genesis);
let expected_kid = ed25519_dalek::SigningKey::from_bytes(&gate_seed)
    .verifying_key()
    .to_bytes();
let nonce_store = Arc::new(NonceStore::new(DRIFT_WINDOW));
```

Both `expected_kid` and `nonce_store` are injected into the middleware
closure the same way `Arc<SessionAuth>` is today. No new wiring
pattern; one more `Arc` alongside the existing ones.

### 4.5 Error responses

| Condition | Status | `X-Auth-Reason` |
|-----------|--------|------------------|
| Header missing | 401 | `missing` |
| Header malformed | 401 | `envelope-malformed` |
| Unknown version | 401 | `envelope-version` |
| Unknown signer (kid mismatch) | 401 | `envelope-signer` |
| Method/path/body mismatch | 401 | `envelope-binding` |
| Outside drift window | 401 | `envelope-drift` |
| Replayed nonce | 401 | `envelope-replay` |
| Signature invalid | 401 | `envelope-signature` |

Body shape mirrors the existing 401 (small JSON, `{"error":"...","detail":"..."}`).
The differentiated `X-Auth-Reason` lets the IronClaw caller distinguish
"my clock is wrong" from "my key derivation is wrong" without leaking
implementation details to attackers.

---

## 5. IronClaw caller

### 5.1 Signing wrapper

Today's `ZpClient` (`src/zp/client.rs:56–79`) holds `bearer: String`.
Post-migration, it holds a signer and signs per-request:

```rust
// src/zp/client.rs (post-migration shape — diff against existing struct)

pub struct ZpClient {
    http: Client,
    base_url: String,
    signer: Arc<ed25519_dalek::SigningKey>,
    kid_hex: String,              // 64-char lowercase hex
    agent: String,
}

impl ZpClient {
    pub fn new(cfg: &ZpConfig, signer: Arc<ed25519_dalek::SigningKey>) -> Result<Self, ZpError> {
        let kid_hex = hex::encode(signer.verifying_key().to_bytes());
        let http = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self { http, base_url: cfg.base_url.clone(), signer, kid_hex, agent: cfg.agent_name.clone() })
    }

    /// Single insertion point: every gate request goes through here.
    fn signed_request(
        &self,
        method: reqwest::Method,
        path_and_query: &str,
        body: Vec<u8>,
    ) -> reqwest::RequestBuilder {
        let claims = zp_gate_envelope::EnvelopeClaims {
            v: 1,
            method: method.as_str().to_string(),
            path: path_and_query.to_string(),
            body_hash: zp_gate_envelope::body_hash_hex(&body),
            ts: chrono::Utc::now().timestamp(),
            nonce: zp_gate_envelope::random_nonce_b64(),  // 16 random bytes → b64url no-pad
        };
        let hash = <zp_gate_envelope::EnvelopeClaims as zp_receipt::Signable>::canonical_hash(&claims);
        let sig = self.signer.sign(&hash);
        let header = zp_gate_envelope::build_header(&claims, &sig.to_bytes());
        self.http
            .request(method, format!("{}{}", self.base_url, path_and_query))
            .header(reqwest::header::AUTHORIZATION, header)
            .body(body)
    }
}
```

`gate_tool_call` and `observe` become two-line wrappers: build the body
bytes via `serde_json::to_vec(&body)`, then `self.signed_request(...)
.send().await`.

### 5.2 Signer loading at startup

`src/app.rs:1171–1196` is the existing init point. New shape:

```rust
// Pre-existing:
let zp_cfg = crate::zp::ZpConfig::from_env().context("…")?;

// New: load Genesis-derived gate signer once (if enabled)
let zp_signer = if let Some(cfg) = zp_cfg.as_ref() {
    let genesis_path = cfg.genesis_record_path.clone();  // see §5.3
    let seed = crate::zp::bootstrap_gate_signer(&genesis_path)?;
    Some(Arc::new(ed25519_dalek::SigningKey::from_bytes(&seed)))
} else { None };

// Existing, modified:
if let (Some(cfg), Some(signer)) = (zp_cfg.as_ref(), zp_signer.as_ref()) {
    let client = crate::zp::ZpClient::new(cfg, signer.clone())?;
    // ...register hook as before
}
```

### 5.3 Genesis access from IronClaw

IronClaw today **does not** load Genesis — it only reads the bearer
token. Post-migration it needs `load_sovereign_root` access. Two
options:

| Option | Shape | Trade-off |
|--------|-------|-----------|
| **A — IronClaw links zp-keys directly** | `IRONCLAW_ZP_GENESIS_PATH` env var points at `~/ZeroPoint/genesis.json`; IronClaw calls `zp_keys::sovereignty::load_sovereign_root(path)?` | Clean composition; one ceremony per IronClaw startup. IronClaw inherits the substrate's biometric prompt at process launch. Adds `zp-keys` (and transitively `keyring`, sovereignty providers) to IronClaw's dep tree. |
| **B — Substrate runs the signer, exposes per-IronClaw signing oracle over Unix socket** | `zp serve` exposes `/internal/sign` on Unix socket; IronClaw POSTs preimage, gets signature | Avoids the dep-tree growth. But: re-introduces a producer-consumer pair (the socket replaces session.json) — the very pattern this design is removing. Reject. |

**Choose A.** It composes with #152 cleanly: IronClaw is just another
consumer of `load_sovereign_root` from the same Genesis. The dep-tree
cost is real but acceptable; IronClaw is already a substrate-aware
process, not an arbitrary third-party tool.

`zp configure exec` (`crates/zp-cli/src/main.rs:1493–1509`) becomes
responsible for setting `IRONCLAW_ZP_GENESIS_PATH` in the child env (in
addition to, then in place of, `ZP_SESSION_TOKEN` during migration).
Default value: `zp_paths::genesis_record_path()`.

**Note on Genesis-path discipline.** IronClaw must never *read*
genesis.json's contents directly — only pass its path to
`load_sovereign_root`. That's the same shape every other Genesis
consumer in the substrate uses. The discipline pin in §10 covers the
derivation-context side; the singular-sovereign-root pin proposed in
`docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md` (not yet landed) covers the
credential-store-read side.

### 5.4 Error handling

The 401 paths in `src/zp/hook.rs:182–192` and `:246–252` keep their
fail-closed posture, with two refinements:

1. **Better error messages.** The old message ("Re-onboard or refresh
   ZP_SESSION_TOKEN") is no longer accurate. New message:
   `"ZP gate rejected envelope (X-Auth-Reason: {reason}). Check Genesis
   derivation. Run \`zp doctor\` for diagnostics."` The `X-Auth-Reason`
   value is read from the response header and surfaced directly —
   operator sees which structural failure occurred.

2. **No `disable()` for envelope-binding errors.** A 401 with
   `envelope-drift` (clock skew) or `envelope-replay` (nonce collision)
   is a transient condition, not "stop trying forever." For these, log
   the error but allow the next request. For `envelope-signer`,
   `envelope-version`, `envelope-malformed` — keep the disable
   behavior; those indicate a real configuration drift that won't
   self-heal.

---

## 6. Migration plan

Six steps, each individually shippable and reversible. Production never
breaks mid-migration because steps 1–3 are strictly additive.

### Step 1 — Land `zp-gate-envelope` crate + signer derivation

Files added:
- `crates/zp-gate-envelope/Cargo.toml`, `src/lib.rs` — claims struct,
  header parse/build, body_hash helper, random_nonce_b64
- `crates/zp-keys/src/gate_signer.rs` + export in `lib.rs` —
  `derive_gate_signer_seed`, `GATE_SIGNER_CONTEXT`

Tests: derivation determinism, known-answer test, header round-trip
(build → parse → equal claims), envelope claims canonical-bytes
stability test.

**No behavior change. Pure additions. Mergeable independently.**

### Step 2 — Gate accepts envelope OR legacy bearer

Files modified:
- `crates/zp-server/src/auth.rs` — `require_auth` adds envelope path as
  priority 1; bearer/cookie/query paths unchanged
- `crates/zp-server/src/envelope_state.rs` (new) — NonceStore, drift
  constant
- `crates/zp-server/src/lib.rs` or wherever router state is built —
  load `expected_kid`, construct `Arc<NonceStore>`, inject into
  middleware closure

Gate now accepts either form. Existing IronClaw deployments continue
to work via bearer. **Strictly backwards-compatible.**

### Step 3 — IronClaw signs envelopes

Files modified:
- `src/zp/config.rs` — add `genesis_record_path` (env
  `IRONCLAW_ZP_GENESIS_PATH`, default `zp_paths::genesis_record_path()`),
  remove `session_token` field
- `src/zp/client.rs` — replace `bearer: String` with
  `signer: Arc<SigningKey>` + `kid_hex`, add `signed_request` helper,
  rewire `gate_tool_call`/`observe` through it
- `src/zp/hook.rs` — refined error messages, selective disable logic
- `src/app.rs:1171–1196` — load gate signer between config and client
  construction
- `crates/zp-cli/src/main.rs:1493–1509` — inject
  `IRONCLAW_ZP_GENESIS_PATH` into child env (in addition to legacy
  `ZP_SESSION_TOKEN`)

**Verify in production:** restart `zp serve`, observe IronClaw makes
successful gate calls without intervention. Simulate 8h+ uptime (set
`ZP_SESSION_MAX_AGE_SECONDS=60` for the test) — calls keep succeeding.

### Step 4 — Remove legacy bearer acceptance from gate

After Step 3 has burned in for at least one operator session in
production:

Files modified:
- `crates/zp-server/src/auth.rs` — `require_auth` drops bearer-token
  path. Cookie path remains (browser surface, scope of #139).
- WS `?token=` path: if browsers depend on it, keep (it shares the
  cookie tier, not the IronClaw tier); otherwise remove.

### Step 5 — Stop minting session.json

Files modified:
- `crates/zp-server/src/auth.rs` — `SessionAuth` (if still needed for
  the browser cookie tier) stops writing `session.json`. The persisted-
  session shape served two consumers: the cookie path (browser, scope
  of #139) and the bearer path (IronClaw, now dead). With the bearer
  path gone, the file's only remaining consumer was `zp configure
  exec`'s `read_zp_session_token_from`, which is also dead.
- Best-effort cleanup nudge in `zp doctor`: warn if
  `~/ZeroPoint/session.json` exists post-migration.

If the cookie tier still needs persistent session state, that's #139's
concern — track separately; do not block this migration on it.

### Step 6 — Delete dead code

See §9 cleanup checklist.

---

## 7. Edge-case treatment table

| Edge case | Treatment |
|-----------|-----------|
| **Clock skew between processes** | Drift window of **±30s** (configurable via `ZP_GATE_DRIFT_WINDOW_SECS`, capped at 300s). Rationale: NTP-synced hosts skew well under 1s; ±30s covers human-noticeable drift while keeping the replay-protection LRU bounded. Outside window → 401 `envelope-drift`. |
| **Replay of valid signed request** | **Nonce-dedup LRU**, scope `(kid, nonce)`, capacity 16 384, age-bounded by drift window (§4.3). Replay → 401 `envelope-replay`. |
| **Genesis-derived signing key compromise** | **Substrate has no revocation primitive today** for derived keys. The only revocation today is Genesis rotation (which rotates *every* derived key). Scope explicitly as a future capability: a `GATE_SIGNER_CONTEXT` bump to `v2` would rotate the gate signer specifically, leaving other derived keys untouched. Document this; do not implement v2 in this round. |
| **Key derivation drift (sides derive different keys from same Genesis)** | Designed out by sharing the `zp-gate-envelope` + `zp-keys::gate_signer` crates. Both sides import the same `derive_gate_signer_seed` function from the same crate. Discipline pin (§10) prevents anyone redefining the derivation outside `crates/zp-keys/src/gate_signer.rs`. |
| **Pre-Genesis state (onboarding ceremony)** | **Out of scope.** Onboarding flows do not call the gate; they create Genesis. Once Genesis exists, gate calls become signable. If a future onboarding step needs gate access before Genesis exists, that step itself must be the one to mint Genesis first — not a workaround in the envelope spec. |
| **Process forks / multi-tenant** | **Out of scope** — #99 territory. The v1 envelope assumes one Genesis per gate. Multi-tenant means multiple Geneses; each tenant's IronClaw would derive its own gate signer; the gate would maintain a per-tenant `expected_kid` set. The header shape already supports this (`kid` identifies which signer); the multi-tenant store is the missing piece. |
| **Cross-machine gate calls** | **Out of scope** for this brief. The envelope shape composes with cross-machine calls — Genesis pubkey is the same across machines for the same identity — but the threat model differs (no shared clock guarantee, no shared LRU). A v1-compatible cross-machine deployment is possible but the operational story (clock sync, replay window, monitoring) deserves its own design. |
| **Operator wants to revoke a specific running process's auth** | Today's `SessionAuth::rotate` provides this for the bearer-token model. The new model has no analogue at the same granularity — the signer derives from Genesis, which is not per-process. Operator can revoke *all* gate access by re-deriving the gate signer with a `v2` context (future capability). Per-process revocation requires per-process signers, which is a multi-tenant / sub-Genesis design (#99). Scope explicitly as out of scope. |
| **Body buffering in middleware** | The verifier must buffer the request body to hash it. Body size cap reuses the existing gate body limit (do not introduce a parallel one). Buffered body is reconstructed into the downstream request via `Request::from_parts`. Confirmed compatible with Axum's middleware story; no streaming endpoints exist today on the gate. If streaming endpoints are added later, they need a different envelope path (e.g., a per-frame envelope) — not v1's concern. |
| **Header injection via malicious `kid`** | `kid` is hex-decoded into `[u8; 32]`. Any non-hex or wrong-length input fails parse before reaching the verifier. Bytewise comparison against `expected_kid` is constant-time-friendly (32-byte constant). |
| **Signature malleability** | Verify goes through `zp_receipt::verify_signature` → `verify_strict` (Seam 5). Non-strict verify is a discipline-pinned forbidden pattern (`no_non_strict_ed25519_verify`). |
| **Empty request body** | `body_hash_hex(b"")` is well-defined (BLAKE3 of empty input). Both sides agree because they call the same helper. |
| **Path normalization across proxies** | `path_and_query` is whatever Axum's `req.uri().path_and_query()` reports — the post-proxy path. IronClaw must build the envelope's `path` field with the same post-proxy form. Since v1 is localhost-only (no proxy in path), they agree by construction. Cross-machine variant (out of scope) would need an explicit canonicalization rule. |

---

## 8. Acceptance test plan

Tests live in `crates/zp-server/tests/envelope_*.rs` and
`crates/ironclaw/src/zp/tests/` per the workspace conventions.

### 8.1 Cryptographic correctness

- **Round-trip:** build envelope from claims + signer → parse header →
  verify against derived pubkey → assert success.
- **Tampered body:** build envelope, swap body bytes, verify → assert
  401 with `envelope-binding`.
- **Tampered method:** build envelope for GET, present as POST →
  assert 401 with `envelope-binding`.
- **Tampered path:** build envelope for `/api/v1/gate/tool-call`,
  present as `/api/v1/cognition/observe` → assert 401.
- **Wrong signer:** sign with a different Genesis-derived seed →
  assert 401 with `envelope-signer`.
- **Signature flipped bit:** valid claims, one bit of `sig` flipped →
  assert 401 with `envelope-signature`.
- **Known-answer test on derivation:** pin the gate-signer derivation
  with a fixed Genesis byte array → assert specific kid pubkey bytes.
  (Mirrors `audit_signer.rs:108–121` known-answer pattern.)

### 8.2 Token rotation no-op

Set `ZP_SESSION_MAX_AGE_SECONDS=60` on the gate for a test run.
- Start `zp serve`, start IronClaw, observe successful gate call.
- Wait 90s.
- Make another gate call → assert success. (Under the legacy bearer
  model, this would 401 because the token aged out.)

### 8.3 Cross-restart

- Start `zp serve`, start IronClaw, gate call succeeds.
- Restart `zp serve` (Genesis re-derived deterministically → same
  `expected_kid`).
- Make another gate call from the same IronClaw process → assert
  success without intervention.
- Restart IronClaw → `load_sovereign_root` re-derives same seed →
  assert next gate call succeeds.

### 8.4 Replay protection

- Capture a valid signed envelope (e.g., proxy/MITM the IronClaw → gate
  request locally).
- Replay it within drift window → assert 401 with `envelope-replay`.
- Replay it outside drift window → assert 401 with `envelope-drift`
  (drift check fires first; verify the error code is the more specific
  one).

### 8.5 Drift window

- Build envelope with `ts = now - 60` (outside ±30s window) → assert
  401 with `envelope-drift`.
- Build envelope with `ts = now + 60` → assert 401 with `envelope-drift`.
- Build envelope with `ts = now - 15` → assert success.

### 8.6 Backwards-compat during migration

Only runs during Step 2 (between envelope landing and legacy removal):

- Present legacy `Authorization: Bearer <session.json token>` → assert
  success (gate still accepts).
- Present new `Authorization: ZP-Sig v=1, ...` envelope → assert
  success.

After Step 4 (legacy removal), the bearer test should be re-asserted as
**must 401** (with reason `missing` because the bearer no longer
matches the new parser's `ZP-Sig` prefix).

### 8.7 Discipline pin

The new discipline pin (§10) is itself a test:
`crates/zp-discipline/tests/no_inline_gate_signer_derivation.rs`.
Runs as part of `cargo test -p zp-discipline`.

---

## 9. Cleanup checklist

After migration is complete (post Step 5), the following code becomes
dead and must be deleted in Step 6. The "every bit counts" principle
requires this is explicit, not deferred.

### Files / functions deleted entirely

| Path | What |
|------|------|
| `crates/zp-server/src/auth.rs:42–56` | `PersistedSession` struct (if cookie tier doesn't need it; see #139 coordination) |
| `crates/zp-server/src/auth.rs:173–181` | `SessionAuth::mint_token` |
| `crates/zp-server/src/auth.rs:197–212` | `SessionAuth::rotate` (if no other caller; verify with grep) |
| `crates/zp-server/src/auth.rs:218–236` | `SessionAuth::verify` (the bearer-token version) |
| `crates/zp-server/src/auth.rs:252–303` | `session_file_path` + `hmac_key_fingerprint` + `load_persisted_session` |
| `crates/zp-server/src/auth.rs:309–349` | `persist_session` |
| `crates/zp-server/src/auth.rs:564–575` | `extract_cookie_token` (only if cookie path is also removed; otherwise keep) |
| `crates/zp-cli/src/main.rs:3992–4017` | `read_zp_session_token` + `read_zp_session_token_from` |
| `crates/zp-cli/src/main.rs:1498–1500` | `child.env("ZP_SESSION_TOKEN", tok)` injection |
| `crates/zp-hardening-tests/tests/phase_session_token.rs` | Bearer-token integration test |

### Field / line removals

| Path | What |
|------|------|
| `crates/zp-server/src/auth.rs:120–124` | HMAC-key derivation from signing-key bytes (`b"zp-session-v1"`) |
| `crates/zp-server/src/auth.rs:126–129` | `max_age_secs` env-var read + 8h default |
| `crates/zp-server/src/auth.rs:686–692` | Stale-cookie clearing branch in `require_auth` (becomes unreachable once bearer path is gone) |
| `src/zp/config.rs:40` (IronClaw) | `optional_env("ZP_SESSION_TOKEN")` |
| `src/zp/config.rs:24` (IronClaw) | `session_token: SecretString` field |

### Env vars no longer used

- `ZP_SESSION_TOKEN`
- `ZP_SESSION_MAX_AGE_SECONDS`

Remove documentation references in:
- `CLAUDE.md` (project root, if mentioned — grep first)
- `docs/RUNTIME-ENV-VARS-*.md` (if such a doc exists)
- IronClaw's `AGENTS.md` / config docs

### Filesystem artifacts

`~/ZeroPoint/session.json` becomes orphaned. Best-effort cleanup: add
a `zp doctor` check that warns if the file exists post-migration. Do
not delete automatically (operator may want to inspect for forensics).

### Tests to delete / rewrite

| Test file | Action |
|-----------|--------|
| `crates/zp-hardening-tests/tests/phase_session_token.rs` | Delete — covers bearer-token plumbing that no longer exists |
| Any test asserting `ZP_SESSION_TOKEN` env-var presence | Update to assert `IRONCLAW_ZP_GENESIS_PATH` instead, or delete if redundant with §8 tests |

---

## 10. Discipline-pin candidate

**Name:** `no_inline_gate_signer_derivation`

**Lives at:**
`crates/zp-discipline/tests/no_inline_gate_signer_derivation.rs`

**Why:** The correctness of the entire scheme depends on both sides
deriving the same key. The structural enforcement is "one helper, one
crate." The pin protects that structure from drift — a future
contributor might be tempted to inline the BLAKE3-keyed derivation
(`blake3::Hasher::new_keyed(...).update(b"zp.gate.request.v1")`) at
their call site rather than depending on `zp-keys`. The first time
that happens, the call site's derivation must agree with the canonical
one. Two months later, when the canonical helper is bumped to v2, the
inline copy is silently stuck on v1 — exactly the "half-state" failure
class this whole brief is removing.

**Pattern:** Forbid `b"zp.gate.request.` (and any future versioned
variant `b"zp.gate.request.vN"`) outside
`crates/zp-keys/src/gate_signer.rs` and the canonical test file.

**Shape — modeled on `no_raw_keychain_service_strings.rs`:**

```rust
//! Discipline: gate-signer derivation must go through the canonical helper.
//!
//! # Why
//!
//! The gate envelope's correctness depends on both signer (IronClaw,
//! future remote callers) and verifier (zp-server) deriving the same
//! 32-byte seed from Genesis. The canonical helper lives at
//! `crates/zp-keys/src/gate_signer.rs::derive_gate_signer_seed`.
//! Inlining the derivation at a call site means a future bump to v2
//! is silently broken on the inlined copy — the "half-state" failure
//! class the genesis-signed-gate-requests design exists to eliminate.

use zp_discipline::Discipline;

#[test]
fn no_inline_gate_signer_context_outside_canonical_module() {
    Discipline::new("no_inline_gate_signer_derivation")
        .cite_invariant("Singular sovereign root (§II.21) + envelope canonical-derivation")
        .rationale(
            "BLAKE3-keyed derivation with the gate-signer context must \
             go through zp_keys::gate_signer::derive_gate_signer_seed. \
             Inline copies drift on context bumps and break envelope \
             verification.",
        )
        // Catches `b"zp.gate.request.v1"`, `b"zp.gate.request.v2"`, etc.
        .forbid_pattern(r#"b"zp\.gate\.request\.v\d+""#)
        // The canonical definition itself, plus its tests.
        .skip_lines_containing("//")
        .assert();
}
```

**Coverage gap acknowledged:** the pattern catches the obvious case
(literal byte string with the context). It does not catch a future
contributor who writes `let ctx: &[u8] = &[0x7a, 0x70, ...]`
byte-by-byte. Same coverage trade-off the other pins make; the
discipline catches the loud case and a code review catches the
creative one.

---

## 11. Acceptance criteria check

Cross-reference against the brief's seven criteria:

| # | Criterion | Where in this doc |
|---|-----------|-------------------|
| 1 | Envelope spec unambiguous (canonical bytes, header format, signature scheme byte-level) | §2.1 (header), §2.3 (canonical bytes), §3 (Ed25519 derivation) |
| 2 | Composes with #152 — gate signer via `load_sovereign_root`, singular root remains singular | §3.3 |
| 3 | Composes with existing `zp-receipt` signing infrastructure — no parallel pipeline | §2.3 (uses `canonical_bytes_of`), §4.2 (uses `verify_signed`), §3.1 (mirrors `audit_signer.rs` shape) |
| 4 | Every edge case has explicit treatment | §7 (13 rows) |
| 5 | Migration plan operationally safe — production can't break mid-migration | §6 (6 steps; Steps 1–3 strictly additive; Step 4 is the only removal and it's guarded by a verified Step 3 burn-in) |
| 6 | Discipline-pin candidate identified | §10 |
| 7 | Cleanup explicit — every file/line that becomes dead code | §9 |

---

## Refs

- Task #167 (IronClaw ZP_SESSION_TOKEN refresh on stale) — closed
- Task #168 (zp serve token auto-rotation) — closed
- Task #152 (Singular sovereign root) — composes with this design
- Task #139 (Substrate-as-Sovereign-IdP) — sibling at browser tier
- Task #143 (Foundation worker signed receipts) — same family at issuance tier
- Task #91 (load-bearing-honest hardening) — the arc this work belongs to
- Investigation brief: `docs/handoffs/genesis-signed-gate-requests-investigation-2026-05.md`
- Superseded sibling: `docs/handoffs/stale-binding-family-investigation-2026-05.md`
- `docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md` — principle + discipline-pin proposal
- `docs/ARCHITECTURE-2026-04.md` § V½ — the six principles this design is grounded in
- `crates/zp-server/src/auth.rs` — current bearer-token issuance + validation (largely dead post-migration)
- `crates/zp-keys/src/audit_signer.rs` — derivation pattern the new gate signer mirrors
- `crates/zp-keys/src/vault_key.rs` — second derivation precedent
- `crates/zp-keys/src/sovereignty/mod.rs:629–653` — `load_sovereign_root` canonical loader
- `crates/zp-receipt/src/canonical.rs` — Seam 17 canonical-bytes pipeline
- `crates/zp-receipt/src/signable.rs` — Seam 20 Signable trait
- `crates/zp-receipt/src/verify.rs:85–96` — Seam 5 verify_signature primitive
- `crates/ironclaw/src/zp/client.rs` — single insertion point for envelope signing
- `crates/ironclaw/src/app.rs:1171–1196` — startup signer-load insertion point
