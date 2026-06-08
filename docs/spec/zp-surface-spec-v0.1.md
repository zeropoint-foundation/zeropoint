# ZP Surface Spec v0.1

*Published 2026-05-25. Versioned independently of ZeroPoint substrate and ZP Console.*

---

## What this spec is for

The ZP Surface Spec defines the contract between **cockpits** (conversational agents) and **ZP Console** (the operator workspace). A cockpit that implements this spec can integrate with any Console that implements it, and vice versa, without either party knowing the other's internals. The spec is transport-agnostic; the HTTP/JSON binding in §5 is the normative default.

---

## Glossary

| Term | Meaning |
|------|---------|
| **Cockpit** | A conversational agent that integrates with ZP Console via this spec (e.g., IronClaw, Ember). |
| **Console** | The operator workspace that composes cockpit contributions into a unified surface. |
| **Orchestrator** | The cockpit role that holds the exclusive right to emit chat, voice, and tool contributions. Exactly one cockpit holds this role at a time. |
| **Session** | The period between a cockpit's registration and unregistration (or timeout). |
| **Tile** | A renderable artifact contributed by a cockpit to Console's workspace layout. |
| **ZP-Sig** | The Genesis-derived Ed25519 per-request envelope scheme. Wire format: `Authorization: ZP-Sig v=1, kid=<hex32>, ts=<unix>, nonce=<b64url_16B>, sig=<b64url_64B>`. |
| **Artifact** | A content-addressed, optionally-signed rendering per `docs/ARTIFACT-LIBRARY-2026-05.md`. Referenced by `artifact_id = hex(blake3(source_manifest ‖ render_config))`. |

---

## 1. Cockpit Identity

A cockpit is identified by a stable `cockpit_id` string (e.g., `"ironclaw"`). A cockpit's cryptographic identity is its Ed25519 keypair; the `kid` is the hex-encoded 32-byte verifying key.

**All cockpit → Console HTTP requests MUST carry:**
```
Authorization: ZP-Sig v=1, kid=<hex_pubkey>, ts=<unix_seconds>, nonce=<b64url_16B>, sig=<b64url_64B>
```

The signature covers `canonical_hash(method, path, body_hash, ts, nonce)` per `zp-gate-envelope` spec. Console verifies the signature against the `kid` registered in §2.1.

**All Console → cockpit event deliveries MUST carry** the same `ZP-Sig` header signed by Console's key. Cockpit SHOULD verify.

---

## 2. Registration and Lifecycle

### 2.1 Register

```
POST /surface/register
Content-Type: application/json
Authorization: ZP-Sig …

{
  "surface_spec_version": "0.1",
  "cockpit_id": "ironclaw",
  "kid": "<hex 32-byte verifying key>",
  "event_url": "https://ironclaw.example/events",
  "capabilities": ["chat", "voice", "tool", "status", "tile"]
}
```

**Response 200:**
```json
{ "session_id": "<opaque string>", "console_version": "0.1" }
```

**Response 400:** `surface_spec_version` major version mismatch.
**Response 401:** invalid ZP-Sig.
**Response 409:** `cockpit_id` already registered in an active session.

Console stores (`session_id`, `cockpit_id`, `kid`, `event_url`, `capabilities`). All subsequent calls from this cockpit are authenticated via the registered `kid`.

### 2.2 Heartbeat

```
GET /surface/heartbeat
Authorization: ZP-Sig …
```

**Response 200:** `{ "session_id": "..." }`
**Response 404:** session not found or expired.

Console polls registered cockpits at its configured cadence (recommended: 30 s). Three consecutive heartbeat failures → Console marks session expired and emits `session.ended` internally.

### 2.3 Unregister

```
DELETE /surface/unregister
Authorization: ZP-Sig …
```

**Response 200.** Console releases orchestrator role if held and cleans session state.

---

## 3. Orchestrator Role

Exactly one cockpit holds the orchestrator role per operator session. The orchestrator is the only cockpit that MAY emit:
- `POST /surface/chat/message`
- `POST /surface/voice/audio` (outbound)
- `POST /surface/tool/invoke`

Any registered cockpit MAY emit `POST /surface/status/update` and `POST /surface/tile/contribute` regardless of orchestrator status.

### 3.1 Transfer

```
POST /surface/orchestrator/transfer
Authorization: ZP-Sig … (current orchestrator or Console admin key)

{ "to": "<cockpit_id>" }
```

**Response 200:** `{ "granted_to": "...", "revoked_from": "..." }`
**Response 403:** requester is not the current orchestrator and not Console admin.
**Response 404:** target cockpit_id not registered.

Console delivers `orchestrator.granted` to the new holder and `orchestrator.revoked` to the prior holder (see §5).

### 3.2 Query

```
GET /surface/orchestrator
```

**Response 200:** `{ "cockpit_id": "...", "since": "<ISO8601>" }`
**Response 204:** no orchestrator currently assigned.

---

## 4. Surface Contributions (Cockpit → Console)

### 4.1 Chat Message

```
POST /surface/chat/message
Authorization: ZP-Sig …

{
  "session_id": "...",
  "text": "...",
  "inference_tier": "high_stakes" | "bulk" | "coding" | "local" | "experimental",
  "receipt_id": "rcpt-..."
}
```

**Required:** orchestrator role. **Required:** `inference_tier`. **Required:** `receipt_id` — the substrate receipt ID for the inference call that produced this message.

`inference_tier` values map to `zp_core::InferenceTier` snake_case variants.

**Response 200:** `{ "attributed_to": "<cockpit_id>:<kid_prefix>" }`
**Response 400:** missing required field.
**Response 403:** not orchestrator.

### 4.2 Voice — Transcript

```
POST /surface/voice/transcript
Authorization: ZP-Sig …

{
  "session_id": "...",
  "text": "...",
  "direction": "in" | "out",
  "speaker": "<cockpit_id or 'operator'>"
}
```

`direction: "in"` = operator-to-cockpit transcript. `direction: "out"` = cockpit-to-operator transcript.
Outbound transcript requires orchestrator role. Inbound may be submitted by any registered cockpit relaying operator input.

**Response 200.**

### 4.3 Voice — Audio Out

```
POST /surface/voice/audio
Authorization: ZP-Sig …

{
  "session_id": "...",
  "audio_b64": "<base64-encoded bytes>",
  "mime_type": "audio/mpeg" | "audio/wav" | "audio/ogg",
  "direction": "out"
}
```

**Required:** orchestrator role and `direction: "out"`. Inbound audio from the operator is delivered to the cockpit via Console's `voice.input` event (§5).

**Response 200.**

### 4.4 Tool Invocation

```
POST /surface/tool/invoke
Authorization: ZP-Sig …

{
  "session_id": "...",
  "tool_name": "...",
  "args": { ... },
  "inference_tier": "..."
}
```

Console forwards to the substrate gate (`POST /api/v1/gate/tool-call`). Returns the gate's decision.

**Required:** orchestrator role and `inference_tier`.

**Response 200:**
```json
{
  "allowed": true | false,
  "reason": "..." | null,
  "receipt_id": "rcpt-..."
}
```

**Response 403:** not orchestrator.

### 4.5 Status Update

```
POST /surface/status/update
Authorization: ZP-Sig …

{
  "session_id": "...",
  "state": "idle" | "working" | "error",
  "detail": "..." | null
}
```

Any registered cockpit. Console displays cockpit status in the workspace surface.

**Response 200.**

### 4.6 Tile Contribution

```
POST /surface/tile/contribute
Authorization: ZP-Sig …

{
  "session_id": "...",
  "tile": {
    "kind": "chain_narration" | "calendar" | "timeline" | "digest" | "custom",
    "artifact_id": "<hex blake3 content address>",
    "title": "...",
    "slot": "primary" | "secondary" | "sidebar"
  }
}
```

Any registered cockpit. `artifact_id` references a content-addressed artifact per `docs/ARTIFACT-LIBRARY-2026-05.md`. Console fetches the artifact from the library and renders it in the declared slot.

**Response 200:** `{ "tile_id": "..." }`
**Response 422:** `artifact_id` not found in library.

---

## 5. Event Delivery (Console → Cockpit)

Console POSTs events to the `event_url` declared at registration. All deliveries carry `Authorization: ZP-Sig` from Console's key.

Cockpit MUST respond HTTP 200 within 5 seconds. Console retries twice with 1 s backoff on non-200 response or timeout. After three failures, Console logs a delivery failure and continues without further retries for that event.

Event body shape:

```json
{
  "event_type": "<type>",
  "session_id": "...",
  "ts": "<ISO8601>",
  "<event-specific fields>"
}
```

### Event Types

**`operator.input`**
```json
{ "event_type": "operator.input", "text": "..." }
```

**`voice.input`**
```json
{ "event_type": "voice.input", "audio_b64": "...", "mime_type": "audio/mpeg" }
```

**`orchestrator.granted`**
```json
{ "event_type": "orchestrator.granted", "previous_holder": "<cockpit_id>" | null }
```

**`orchestrator.revoked`**
```json
{ "event_type": "orchestrator.revoked", "new_holder": "<cockpit_id>" }
```

**`session.ended`**
```json
{ "event_type": "session.ended", "reason": "operator_logout" | "timeout" | "error" }
```

---

## 6. Trust Attribution

Every contribution (§4) MUST be signed by the cockpit's registered `kid` via ZP-Sig.

The `receipt_id` field on `chat.message` and `tool.invoke` MUST reference a receipt present in the substrate's audit chain. Console MAY verify this reference; a missing receipt is not a protocol error but SHOULD be surfaced as an attribution gap.

Console MUST display attribution by `cockpit_id` + `kid` fingerprint (first 8 hex chars) on all operator-visible chat messages and tile contributions.

The trust thread: `operator sees contribution → cockpit_id + kid → receipt_id in chain → substrate gate decision → Genesis-derived key`. End-to-end Genesis-rooted provenance.

---

## 7. Tier Integration

`inference_tier` is a required field on `chat.message` and `tool.invoke`. Valid values:

| Value | Meaning |
|-------|---------|
| `high_stakes` | High-precision reasoning, ~20% of budget |
| `bulk` | Agent loops and summarisation, ~60% of budget |
| `coding` | Code generation and review |
| `local` | Local inference only, offline/privacy-sensitive |
| `experimental` | New hosts under evaluation; receipts flagged |

Console annotates the proxied inference call with the declared tier. The substrate gates and meters accordingly. Cockpit MUST NOT declare a tier it did not actually use for the inference that produced the contribution.

---

## 8. Versioning and Forward Compatibility

Registration MUST include `surface_spec_version: "0.1"`.

**Major version mismatch** (e.g., cockpit declares `"1.0"` against Console's `"0.1"`): Console MUST reject with HTTP 400. Major version bumps are wire-incompatible.

**Minor version mismatch** (e.g., cockpit declares `"0.2"` against Console's `"0.1"`): Console MUST accept and include a `"version_warning"` in the registration response. The cockpit MUST NOT rely on features not defined in the Console's supported version.

**Additive fields:** new optional request fields introduced in minor versions MUST be ignored by implementations that don't support them. New event types MUST be silently ignored by cockpits that don't handle them.

**Changelog:** `docs/spec/CHANGELOG.md` tracks every spec change with rationale and migration notes.

---

## Implementation notes (non-normative)

- A cockpit that shares a process with Console MAY use in-process channels instead of HTTP, provided the same ZP-Sig authentication is applied to all messages before delivery and verification.
- The `event_url` MAY point to a Cloudflare Tunnel endpoint. Console is not required to maintain a persistent connection; webhook delivery is fire-and-forget with retry.
- Cockpits SHOULD implement the event receiver before the contribution verbs, so they can receive `orchestrator.granted` before emitting chat.
- The `capabilities` array in registration is advisory. Console MAY use it to display supported surfaces; it does not substitute for actual capability enforcement (enforced by orchestrator checks on individual endpoints).

---

*Spec version: 0.1 — 2026-05-25*
*Changelog: `docs/spec/CHANGELOG.md`*
*Design rationale: `docs/handoffs/zp-surface-spec-design-2026-05.md`*
