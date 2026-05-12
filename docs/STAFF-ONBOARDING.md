# Staff Onboarding Runbook

*ZeroPoint Foundation board of directors — D1 operator setup, key generation, document delivery.*

Tracks issue #294. Source of truth for the operator state is
`zeropoint.global/migrations/0006_seed_operators.sql` +
`zeropoint.global/migrations/0007_fix_director_capabilities.sql`. This runbook
operationalizes those rows into actual onboarded humans.

---

## 1. Current state

The five directors are seeded into D1. Bearer-session auth (HMAC, 24h TTL,
`src/auth/session.js`) works against the placeholder zero public key, so
directors can sign in and exercise their capabilities today. What's missing is
the real Ed25519 keypair per director, the welcome packet, and a recorded
ceremony for each.

| ID | Name | Email | Role | Public key | Onboarded |
|------|----------|-----------------------------------|--------------------|------------|-----------|
| ken | Ken | ken@zeropointfoundation.org | executive_director | placeholder | partial |
| katie | Katie | katie@zeropointfoundation.org | treasurer | placeholder | not started |
| carlie | Carlie | carlie@zeropointfoundation.org | secretary | placeholder | not started |
| louise | Louise | louise@zeropointfoundation.org | director | placeholder | not started |
| lorraine | Lorraine | lorraine@zeropointfoundation.org | director | placeholder | not started |

`onboarded_at` is set to insert-time on every row by the seed migration. It is
not a reliable signal of ceremony completion — track the columns in §6 instead.

---

## 2. Capability set per director

Pulled from migration 0007 (current state). The brief's shorthand is reproduced
in the second column for cross-reference.

| Director | Brief shorthand | Actual capabilities (D1) |
|----------|-----------------|--------------------------|
| ken | `workspace:admin` (root) | `mail:*`, `docs:*`, `media:*`, `tasks:*`, `operators:read`, `receipts:read`, `admin:*` |
| katie | mail:read:\*, mail:send/manage:katie, docs, tasks, receipts | `mail:read:*`, `mail:send:katie`, `mail:manage:katie`, `mail:send:info`, `docs:read`, `docs:write`, `tasks:read`, `tasks:write`, `receipts:read` |
| carlie | mail:read:\*, mail:send/manage:carlie, docs, tasks, receipts | `mail:read:*`, `mail:send:carlie`, `mail:manage:carlie`, `mail:send:info`, `docs:read`, `docs:write`, `tasks:read`, `tasks:write`, `receipts:read` |
| louise | mail:read/manage/send:louise, mail:read:info/board, docs, tasks, receipts | `mail:read:louise`, `mail:manage:louise`, `mail:send:louise`, `mail:read:info`, `mail:read:board`, `docs:read`, `tasks:read`, `receipts:read` |
| lorraine | mail:read/manage/send:lorraine, mail:read:info/board, docs, tasks, receipts | `mail:read:lorraine`, `mail:manage:lorraine`, `mail:send:lorraine`, `mail:read:info`, `mail:read:board`, `docs:read`, `tasks:read`, `receipts:read` |

### Discrepancies — resolution status

1. **Ken's `workspace:admin` grant** — APPLIED + VERIFIED on 2026-05-06.
   Wrangler `UPDATE` ran clean (1 command, 0.88ms). Fresh session token
   carries `workspace:admin` alongside the prior per-domain caps. Live:
   `GET /api/receipts` now returns 200 with the audit chain (26 entries
   at apply time). The denied attempt that motivated this fix is itself
   in the chain at `2026-05-06T01:41:11 auth:denied op=ken` — denials
   are signed receipts too, and that one is now the cryptographic record
   of why the grant happened. Procedure preserved in
   `docs/onboarding/grant-ken-workspace-admin.md` for the audit trail.

2. **Duplicate `GET /api/operators` route** — DEPLOYED + VERIFIED on 2026-05-06.
   Pre-auth listing now at `/api/operators/active` (id+name only).
   `GET /api/operators` is admin-gated and returns full director records
   (id, name, email, role, active, onboarded_at). Live tests:
   anonymous → 401, Louise → 403 + `{"required":"workspace:admin"}`,
   Ken → 200 with all five directors. The pre-auth path returns the
   expected shape (id+name only) for the login dropdown.

3. **`DEFAULT_CAPABILITIES` in `capabilities.js` is stale** — OPEN.
   References "Kalyn" (successor) and "Lorrie" (officer), neither in the
   current seed. Either update to the current board or remove if
   migrations are the source of truth. Low urgency; nothing currently
   calls these defaults.

4. **Successor — conditional (named default, quorum fallback)** — DECIDED.
   Two paths: Ken designates a successor while in role (Path A, default);
   if Ken dies or is incapacitated before designating, the directors elect
   the most qualified successor by quorum (Path B). The chain decides
   which path is in play by examining receipts. See §8 for the full
   design sketch including trigger conditions for the fallback. Until the
   capabilities ship, succession is a paper procedure executed by Ken
   updating D1 per the directors' written decision.

---

## 3. Per-director onboarding sequence

The director runs a guided wizard at `zeropointfoundation.org/onboard/`
on their own device while Ken is on a call coaching them through it.
Every state change is a signed receipt — the chain is the record of
completion. Ken does not need to run any wrangler commands during the
ceremony; the wizard self-completes.

### Director-facing flow (5 phases)

1. **Welcome** — picks themselves from the active director list.
2. **Creating identity** — Ed25519 keypair is generated locally via
   WebCrypto. Private key never leaves the device.
3. **Registering** — public key is submitted to a one-shot endpoint
   (`POST /api/onboard/register-identity`) that succeeds only while the
   placeholder is still in place. `onboarded_at` is updated to the real
   completion timestamp at the same moment.
4. **Recovery phrase** — 24-word BIP39 mnemonic, derived from the seed,
   is shown for the director to write on paper. Continue is disabled
   until they confirm.
5. **Secure sign-in** *(optional but strongly nudged)* — registers a
   WebAuthn passkey on the device. Maps to whatever the platform offers:
   Face ID / Touch ID / Windows Hello (face/fingerprint/PIN) / Android
   biometrics / hardware key. Skipped silently if no platform
   authenticator is available.
6. **Welcome aboard** — capability listing in plain English plus a live
   demonstration of the governance gate (one allowed action, one
   refused; both receipts emitted).

### Ken's role on the call

Coaching only — explain what's happening, answer questions, watch for
problems. No buttons to press, no commands to run. If something goes
wrong, the wizard surfaces a clear error and Ken can investigate via
the audit chain (`GET /api/receipts?subject=<director-id>&claim_prefix=onboard:wizard:`).

### Subsequent sign-ins

Directors visit `zeropointfoundation.org/signin/`. The page lists
active directors with a "Passkey ready" badge for those who have
registered one. Clicking their name triggers the platform's secure-unlock
prompt — face, fingerprint, or PIN — and lands them in the workspace
at `/mail/`. Directors without a registered passkey fall through to the
operator-id session (a temporary state until they re-onboard or
register a passkey from settings).

---

## 4. Documents to deliver

Each director receives the same packet plus a role-specific page.

| Document | Source | Notes |
|----------|--------|-------|
| Welcome letter | `docs/onboarding/<director>.md` | Role-specific. One per director. |
| Foundation overview | `docs/whitepaper-v2.md` (excerpt) | 1-page distillation, not the full whitepaper. |
| Capability sheet | This doc, §2 | Their row only, expanded into plain English. |
| Security guidance | New: `docs/onboarding/security-basics.md` | Recovery mnemonic handling, key hygiene. |
| Acknowledgment of role | DocuSign envelope (#304) | Signed by director, countersigned by Ken. |

---

## 5. Sovereignty mode (production path)

Per `docs/PRODUCTION-GENESIS-CHECKLIST.md`, production keys must be backed by a
real sovereignty provider — Touch ID Secure Enclave, Trezor, or hardware
quorum — not file or login-password. The current state (zero placeholders +
session bearer tokens) is acceptable for soft launch but **must be hardened
before any director-signed receipt represents a binding decision**.

When ready to harden:
1. Each director re-runs Step 1 with their chosen provider (Touch ID for the
   Mac users, Trezor for those who want hardware).
2. The new public key supersedes the old one in `public_key_hex`. The old key
   is revoked via a `succession_events` row (`event_type = 'key_rotation'`).
3. Re-test Step 6.

---

## 6. Status tracker

Update this table as ceremonies complete. Receipt IDs are the audit-chain
entries from Step 6 — those are the cryptographic record of completion, not
the timestamp.

| Director | Step 1 keys | Step 2 submitted | Step 3 in D1 | Step 4 packet | Step 5 first login | Step 6 receipts (success / denied) | Step 7 marked |
|----------|:-----------:|:----------------:|:------------:|:-------------:|:------------------:|:-----------------------------------:|:-------------:|
| ken      | — | — | — | — | — | — / — | — |
| katie    | — | — | — | — | — | — / — | — |
| carlie   | — | — | — | — | — | — / — | — |
| louise   | — | — | — | — | — | — / — | — |
| lorraine | — | — | — | — | — | — / — | — |

---

## 7. Open dependencies

These block or shape full director onboarding.

| Dependency | Issue | Why it matters |
|------------|-------|----------------|
| Email client UI deployed | #325 | Without it, "deliver packet via workspace mail" isn't real. Falls back to external email + DocuSign. |
| DocuSign envelope wired | #304 | Step 4 acknowledgment + Step 7 formal sign-off rely on it. |
| Production sovereignty | n/a (`PRODUCTION-GENESIS-CHECKLIST.md`) | Section 5 above. Required before binding receipts. |
| Bridge UI keygen flow | n/a | Step 1 in the production path. Currently directors would need a `zp` CLI on a Mac, which is operator-friction for non-technical directors. |

---

## 8. Succession — conditional (design sketch)

Two paths, only one of which fires per succession event.

- **Path A — named succession** (preferred, default).
  The genesis holder designates a successor while in role. The designation
  is itself a signed receipt; the successor takes office on the genesis
  holder's departure.

- **Path B — quorum election** (fallback).
  Activates only when Path A has failed: the genesis holder is no longer
  able to designate (death, incapacity) and no valid Path A designation
  exists in the chain. The directors elect the most qualified successor
  by quorum.

The chain decides which path is in play by examining the receipt history,
not by external configuration. State is derived.

### 8.1 Path A — named succession (default)

The genesis holder emits a `succession:designate` receipt naming a
successor at any time. The most recent valid designation is the active
one — the genesis holder can revoke or re-designate, and each emission is
itself a receipt that the chain preserves.

**Receipt shape:**
```
claim:    succession:designate
subject:  <successor-operator-id>
metadata: { effective: "on-departure" | "on-incapacity" | "immediate" }
```

**Capability:** `succession:designate` — granted exclusively to the
genesis holder (i.e., implicit in `workspace:admin`).

**On the genesis holder's departure** (resignation, retirement, planned
transition), the designated successor invokes the role transition with a
`succession:invoke` receipt referencing the active designation. The
designation IS the authority — no quorum vote is required because the
directors already trusted the genesis holder's judgment when they joined
the foundation.

### 8.2 Path B — quorum election (fallback)

Activates only when **both** of the following are true at the moment a
director attempts to open an election:

1. The genesis holder cannot or has not designated a successor (no valid
   `succession:designate` receipt exists, or the named successor is also
   unable to take the role).

2. The genesis holder is unable to designate one now — death,
   incapacity, or unavailability per the trigger condition (§8.3).

A director with `succession:nominate` emits `succession:open` to start
the election window. From there:

| Step | Receipt | Notes |
|------|---------|-------|
| 1. Open | `succession:open` | Subject = reason. References the incapacity attestation that authorized opening. |
| 2. Nominate | `succession:nominate` | Each director may nominate one or more candidates from any active operator. |
| 3. Deliberate | (off-chain) | Directors weigh "most qualified" against the foundation's bylaws. Not enforced in code. |
| 4. Vote | `succession:vote` | One vote per director per close. Later votes from the same director update; chain shows the change. |
| 5. Tally | (derived) | At any moment: count distinct director→candidate mappings, latest-wins per director. When any candidate's count reaches the quorum threshold, election is decided. |
| 6. Close | `succession:close` | Names the winner, references the open and the deciding-vote receipts. The winner derives `succession:invoke` from the closed election. |
| 7. Apply | normal receipts under `succession:invoke` | New genesis holder rotates capabilities, updates operator roles, etc. |

**Quorum parameters (initial proposal):**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| N (electors) | 4 (all directors except the deceased/incapacitated genesis holder) | The genesis holder cannot vote in their own succession. |
| M (threshold) | 3 of 4 | Tolerates one absent or dissenting director; prevents 2-vs-2 deadlock. |
| Eligible nominees | any active operator | The election handles authority transition; the capability model handles role transition afterward. |
| Election window | 14 days | Long enough for deliberation, short enough to avoid drift. Extendable by quorum. |

**On "most qualified."** The chain records who was nominated and who won.
It does not enforce qualification criteria — that's the directors'
deliberation, applied against the foundation's bylaws. The bylaws should
spell out the criteria (mission alignment, technical understanding,
governance experience, time commitment) so that the deliberation is
principled, not ad hoc. That's a bylaws task, not a chain task.

### 8.3 Trigger condition for Path B — DECIDED: hybrid

Path B is allowed to open when **both** of the following are true:

1. **Silence gate.** The genesis holder has emitted no signed receipt for
   30 consecutive days.

2. **Director attestation.** Three of four directors co-sign a
   `succession:attest` receipt asserting the genesis holder cannot
   fulfill the role.

Either condition alone is insufficient. The silence gate alone would
conflate vacation or sabbatical with incapacity. The attestation alone
would let three directors declare a healthy genesis holder incapacitated
and force an election. Both together require a real period of inactivity
*and* the directors' explicit, signed assessment that the inactivity is
permanent.

**Reclaim path.** If the genesis holder reappears during the silence
period, the timer resets on the next genesis-signed receipt. If they
reappear after the window has opened but before the close, they may emit
a `succession:reclaim` receipt that closes the open election. The
nominations, votes, and attestation receipts remain in the chain — the
record of "we thought you were gone, here's what we were prepared to do"
is itself part of the foundation's history.

**Tunables.** The 30-day silence period and 3-of-4 attestation threshold
are starting parameters. They can be revised by a separate quorum action
before any election is open. They cannot be revised mid-election.

**Considered alternatives** (preserved for the decision record):
- *Pure attestation* (3-of-4 anytime, no silence gate) — rejected: lets
  three directors override a healthy genesis holder.
- *Pure time-based dead-man's switch* (silence triggers election with no
  attestation) — rejected: conflates absence with incapacity.

### 8.4 Capability additions

To implement either path, the capability model needs:

| Capability | Holder | Purpose |
|------------|--------|---------|
| `succession:designate` | genesis holder (implicit in `workspace:admin`) | Path A — name the successor while in role. |
| `succession:nominate` | every director | Path B — propose candidates during election. |
| `succession:vote` | every director except the (deceased/incapacitated) genesis holder | Path B — cast a vote per election close. |
| `succession:attest` | every director | Path B — sign the incapacity attestation under §8.3. |
| `succession:invoke` | (derived) | The active successor — either Path A's designee on departure, or Path B's elected winner. Never pre-granted. |

`succession:invoke` is intentionally derived from chain state rather than
granted as a static capability — that keeps "who is in charge" a
property of the chain, not a row in D1 that someone could change without
authorization.

### 8.5 Until then

Succession is a paper procedure: the directors meet, write down the
decision, and Ken executes the resulting D1 changes manually. The paper
record sits in the secretary's archive. When the capabilities above ship,
the paper procedure retires — but the paper records stay in the archive
as the historical record before the chain became the system of truth.
