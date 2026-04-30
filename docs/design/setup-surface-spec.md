# Setup & Maintenance Surface — Design Spec

**Phase 7 · S7-2 through S7-6**
**Status:** Planned
**Route:** `/setup`

## Purpose

The Setup & Maintenance surface is the post-genesis counterpart to onboarding.
Onboarding is a one-shot linear ceremony that establishes identity. Setup is an
always-available operational panel for managing that identity over time.

Where onboarding asks "who are you?", Setup asks "what do you need to change?"

## Access Model

- Available only post-genesis (redirect to `/onboard` if no genesis.json)
- Same auth gate as dashboard (session cookie or localhost bypass)
- Destructive actions (re-key, provider change) require sovereignty confirmation
  (password, biometric, or hardware sign depending on current provider)

## Panels

### 1. Identity Overview (read-only unless acting)

Shows current state at a glance:
- Operator name
- Sovereignty provider + display name
- Genesis key fingerprint + creation date
- Key chain depth (Genesis → Operator → Agent)
- Trust tier level

### 2. Sovereignty Provider Management (S7-3)

**Change Provider** — migrate from one sovereignty mode to another.

Flow:
1. Confirm identity with current provider (password entry, Touch ID, Trezor sign)
2. Select new provider from available options (same catalog as onboarding Step 1)
3. New provider enrollment (password setup, biometric enrollment, hardware pairing)
4. Re-derive operator key under new provider
5. Emit rotation receipt linking old → new
6. Update genesis.json sovereignty_mode field
7. Show confirmation + new recovery kit if applicable

Constraints:
- Cannot downgrade trust tier (Trezor → login_password blocked unless explicit override)
- Must pass governance gate (SovereigntyRule evaluates provider transitions)
- Emits `key:rotation` and `sovereignty:migration` receipts

### 3. Key Rotation (S7-3)

**Rotate Operator Key** — scheduled or manual key rotation.

- Shows current key age, rotation schedule, last rotation date
- "Rotate Now" button triggers operator key rotation with parent co-signing
- Rotation certificate emitted and persisted
- Vault re-encryption under new derived key
- All active sessions invalidated post-rotation

### 4. Recovery Kit (S7-4)

**Export & Verify** — recovery kit management.

- View BIP-39 mnemonic (requires sovereignty confirmation to reveal)
- "Export Recovery Kit" generates a printable/saveable package:
  - Mnemonic words
  - Genesis key fingerprint for verification
  - Recovery instructions
  - QR code for mnemonic (optional, user toggle)
- "Verify Recovery Kit" — user enters mnemonic, system confirms it derives the correct genesis key
- Shows last verification date, suggests periodic re-verification

### 5. Genesis Transcript (S7-5)

**Ceremony Record** — read-only view of genesis history.

- Full genesis ceremony transcript with timestamps
- Receipt chain walkthrough (each step is a receipt with hash link)
- Signed attestation verification (click any receipt to verify signature)
- Provider enrollment evidence
- "Replay" mode — step through the ceremony as it happened (read-only)

### 6. Fleet Enrollment (S7-6)

**Node Onboarding** — bring new machines into the fleet.

- Generate enrollment token (time-limited, single-use)
- QR code + CLI command for the new node
- Shows pending enrollments awaiting approval
- Approve/reject incoming node requests
- Per-node trust tier assignment
- Policy set selection for new nodes

## Architecture

### Route Structure

```
GET  /setup                          → setup page (HTML)
GET  /api/setup/identity             → current identity state
POST /api/setup/sovereignty/confirm  → confirm current provider (challenge-response)
POST /api/setup/sovereignty/migrate  → initiate provider migration
POST /api/setup/keys/rotate          → trigger key rotation
GET  /api/setup/recovery/mnemonic    → reveal mnemonic (requires confirmation)
POST /api/setup/recovery/verify      → verify user-entered mnemonic
GET  /api/setup/genesis/transcript   → genesis transcript + receipt chain
POST /api/setup/fleet/enroll-token   → generate enrollment token
GET  /api/setup/fleet/pending        → pending enrollment requests
POST /api/setup/fleet/approve        → approve/reject enrollment
```

### Server Side

- New module: `crates/zp-server/src/setup/mod.rs`
- Submodules: `identity.rs`, `sovereignty.rs`, `keys.rs`, `recovery.rs`, `transcript.rs`, `fleet.rs`
- Shared confirmation gate: `confirm_sovereignty()` — reusable challenge-response
  that works across all providers (password check, biometric prompt, hardware sign)
- All mutations emit receipts and audit entries
- Governance gate evaluation on provider transitions and key rotations

### Client Side

- `crates/zp-server/assets/setup.html` — page shell
- `crates/zp-server/assets/setup.js` — panel logic
- `crates/zp-server/assets/setup.css` — styling (matches dashboard/onboard aesthetic)
- Uses same WebSocket pattern as onboard for real-time feedback during migrations
- Panels are lazy-loaded sections (not separate pages)

### Security Considerations

- Every destructive action requires fresh sovereignty confirmation (no cached auth)
- Provider migration is a two-phase commit: old provider confirms, new provider enrolls,
  then atomic switchover. Failure at any point rolls back cleanly.
- Mnemonic display requires explicit confirmation and auto-hides after 60 seconds
- Fleet enrollment tokens are BLAKE3-hashed, single-use, 15-minute TTL
- Rate limiting on all confirmation endpoints (reuse existing rate limiter)

## Dependencies

- Existing: `zp-keys` (rotation), `zp-receipt` (chain), `zp-audit` (logging),
  `zp-config` (genesis.json), `zp-trust` (tier enforcement)
- New: sovereignty confirmation abstraction (currently inline in onboard genesis;
  needs extraction into shared utility)

## Implementation Order

1. **S7-2**: Route + page shell + identity overview panel (read-only, quick win)
2. **S7-5**: Genesis transcript viewer (read-only, uses existing data)
3. **S7-4**: Recovery kit export/verify (mostly UI over existing BIP-39 logic)
4. **S7-3**: Provider migration + key rotation (most complex, needs confirmation gate)
5. **S7-6**: Fleet enrollment (builds on Phase 5 fleet registry)

## Relationship to Onboarding

| Concern | Onboarding | Setup |
|---------|-----------|-------|
| When | Pre-genesis (one-shot) | Post-genesis (always) |
| Tone | Guided narrative, linear | Operational, panel-based |
| Genesis | Creates it | Views/verifies it |
| Provider | Chooses initial | Changes it later |
| Recovery | Shows kit once | Exports/verifies anytime |
| Keys | Generates | Rotates/manages |
| Fleet | N/A | Enrolls nodes |

The two surfaces share no code except the sovereignty provider catalog
(which should be extracted into a shared module both can import).
