# Multi-Tenant Foundation: Organizational Substrate

*Drafted 2026-05-11. Candidate for folding into ARCHITECTURE-2026-05.md as
section II.16. Companion to AGENTIC-SURFACE-2026-05.md (II.14),
SIGNATURES-2026-05.md (II.15), PUBLIC-PRIVATE-SEPARATION-2026-05.md.*

## The reframe

ZeroPoint's substrate principles include "there is no center" (V½). That
principle governs **between-organizations** trust: no remote authority
dictates the contents of your audit chain or the validity of your
sovereignty.

The principle does *not* mean every individual must run their own
substrate. **Within** an organization, having a center is normal and
correct. ZeroPoint Foundation IS a center for Foundation operations —
that's what makes it a foundation rather than a federation of
sovereign individuals.

ZP supports both deployment patterns:

- **Federated-sovereign-individuals**: every person runs their own
  substrate; trust between them is established peer-to-peer via mesh +
  trust portability (V.5).
- **Organizational-substrate**: one substrate per organization,
  organization's members authenticate to it as clients; organization
  participates in federated trust externally.

The Foundation uses the organizational-substrate pattern. This is the
architecture for that.

## Three load-bearing decisions

| Decision | v1 choice | Why |
|----------|-----------|-----|
| Substrate location | **APOLLO** (Ken's primary dev machine) | Already has the substrate, vault, Genesis material. Moving to dedicated infrastructure later is a planned migration, not a v1 blocker. |
| Member authentication | **Passkeys / WebAuthn** | Aligns with "identity is a key" (II.6). Universal browser support. Device-bound — fits ZP's threat model and recovery story (lose a device → revoke delegation → issue new one for new device). |
| Foundation Genesis | **Single Ken-held key for v1; quorum on hardware wallets (Trezor) when Foundation grows beyond 2-3 people** | Standard sovereignty evolution path. Single key is operationally simple; hardware quorum is the production state. Quorum work picks up the multi-signing infrastructure already drafted in CLAUDE.md (M-of-N Trezors, Shamir-or-threshold). |

These three decisions drive everything below.

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  EXTERNAL                                                       │
│                                                                 │
│  github.com/zeropoint-foundation/* (public reference impl)      │
│  External counterparty signing flows                            │
│  Public site (zeropoint.global)                                 │
└─────────────────────────────┬──────────────────────────────────┘
                              │ (Foundation boundary)
┌─────────────────────────────▼──────────────────────────────────┐
│  FOUNDATION INTERNAL (one substrate, all members)               │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Foundation Web UI (foundation.zeropoint.global)         │    │
│  │  - Passkey/WebAuthn enrollment                           │    │
│  │  - Member dashboards (per access tier)                   │    │
│  │  - IronClaw chat interface (per-member tenant)           │    │
│  └────────────────────────┬────────────────────────────────┘    │
│                           │                                      │
│  ┌────────────────────────▼────────────────────────────────┐    │
│  │  IronClaw (multi-tenant, hosted on APOLLO)               │    │
│  │  - One ironclaw process; per-member identity routing     │    │
│  │  - Each member's IronClaw session governed by ZP         │    │
│  └────────────────────────┬────────────────────────────────┘    │
│                           │ (ZP gRPC; gate evaluation, etc.)     │
│  ┌────────────────────────▼────────────────────────────────┐    │
│  │  ZP Substrate (one install on APOLLO)                    │    │
│  │  - Foundation vault (shared operational secrets)         │    │
│  │  - Foundation audit chain (collective history)           │    │
│  │  - Foundation documents (content-addressed store)        │    │
│  │  - Foundation Genesis (Ken-held v1, quorum later)        │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

Single ZP substrate. Single IronClaw instance (multi-tenant). Members
access via Foundation web UI hosted on the same machine (initially) or
via direct CLI (technical members). All member actions land on the
Foundation chain, attributable to the specific member who initiated.

## Identity hierarchy

Foundation has a **delegation hierarchy** rooted at the Foundation Genesis:

```
Foundation Genesis Key (Ken initially; quorum eventually)
        │
        ▼
   Operator Key(s)
   (full substrate authority; signs delegations to members)
        │
   ┌────┼────┬────────┬────────┐
   ▼    ▼    ▼        ▼        ▼
  Mbr1 Mbr2 Mbr3   Observer1 Observer2
  (broad-scope)   (read-scope or specific-action-scope)
```

Each member identity is a delegation grant from the Operator, scoping
the member's allowed actions on the Foundation substrate. The
delegation:

- Names the member (`ActorRef.id = "alice@foundation"`)
- Declares the allowed scope (list of action types the member can
  initiate, or "all-actions" for full members)
- Has an expiry / renewal cadence
- Is itself a chained receipt — every member onboarding is visible in
  the Foundation chain

When a member acts (signs a document, runs a tool, contributes to a
discussion that lands on chain), their receipt's `issuer` field is
*their* identity, and the chain proof traces back through their
delegation to the Operator and ultimately to Foundation Genesis.
Verifiers can attribute every action to the human who initiated it,
even when channeled through IronClaw or a web UI.

**Foundation-as-entity is the intersection of authorized actions by its
authorized members.** There's no separate "Foundation actor" that takes
actions distinct from the humans who direct it. When the Foundation
publishes a statement, that statement is co-signed by however many
members the statement requires (operator alone for routine matters;
quorum of members for high-stakes decisions; full quorum for things
that bind the organization's identity).

## Member types

| Type | v1 access | Authentication | Use cases |
|------|-----------|----------------|-----------|
| **Operator** | Full substrate authority; issues/revokes delegations; configures infrastructure | Operator key (hardware-attested when quorum is in place) + passkey for web access | Ken initially. Eventually 2-3 senior members. |
| **Member (technical)** | Broad action scope; full read of Foundation chain; can act on Foundation's behalf within delegation | Passkey (WebAuthn) + optional CLI access with operator-issued credentials | Engineers, technical contributors. |
| **Member (non-technical)** | Same scope as technical, but web-only | Passkey (WebAuthn) | Operations, content, business development. |
| **Observer** | Read-only on declared surfaces (e.g., financial dashboards, governance proposals) OR scoped write (e.g., can co-sign board ratifications but not modify infrastructure) | Passkey (WebAuthn) | Advisors, board members, legal counsel. |

The CLI path is only for technical members who want it; non-technical
members get a more constrained surface via web. Both paths produce the
same kind of cryptographic receipts attributable to the same member
identity.

## Privacy tiering within the Foundation

The Foundation's working principle: **internal work is mostly shared
across team; private to outside.** Tiering implements this:

| Tier | Visibility | Default for what |
|------|-----------|------------------|
| **Public** | Anyone | Substrate code, architecture docs, foundation-stack reference impl, anonymous public statements, anything we put on github.com/zeropoint-foundation/* |
| **Foundation team** | All authenticated members (any tier) | Most operational data: governance decisions, meeting notes, project status, shared documents, the audit chain, the vault's non-credential entries |
| **Leadership** | Operator + designated members (initially Ken-only; expands) | High-stakes partner negotiations in progress, financial decisions before ratification, member compensation discussions |
| **Member-private** | One specific member + Operator | Compensation specifics, individual performance feedback, member-specific delegations |

Most things default to **Foundation team** (Tier 2) — broad internal
transparency is the norm. Tiers 3 and 4 are exceptions for specific
sensitivities, not default postures.

The vault's namespace structure mirrors this:
```
providers/*                          → Foundation team (shared credentials)
tools/<tool>/*                       → Foundation team (per-tool configuration)
documents/<hash>                     → Tiered (per-document ACL in delegation)
members/<member>/*                   → Member-private (operational data for that member)
leadership/*                         → Leadership-only (in-flight high-stakes)
```

Chain receipts are universally readable by authenticated members; what
varies is the **document body** for documents linked to receipts. The
chain proves *that* a high-stakes decision was made; the body might
only be accessible to the leadership tier that made it.

## Authentication: Passkeys / WebAuthn

Standard WebAuthn flow:

1. Member enrolls a passkey on first sign-in (Operator-generated
   enrollment token validates them).
2. Passkey lives in the member's device (TouchID, Windows Hello,
   YubiKey, etc.) — non-exportable, hardware-backed.
3. Every subsequent sign-in to `foundation.zeropoint.global` uses the
   passkey — no passwords, no shared secrets, no recoverable tokens.

**Passkey is the member's authentication, not their signing key.**
Server-side, each member has a substrate-native operator-keyed
delegation. When the member acts, the server confirms the WebAuthn
assertion authenticates the member, then the substrate signs their
action with the member's delegation key.

This means:
- **Device loss is recoverable.** Member tells Operator "I lost my
  laptop." Operator revokes the member's current passkey, issues a new
  enrollment token, member enrolls a passkey on the replacement device.
  Their substrate identity (member name, delegation scope, history)
  carries over.
- **Multi-device is supported.** Member can enroll multiple passkeys
  (laptop, phone, hardware key as backup). Each works independently.
  Loss of one doesn't invalidate the member's identity.
- **Compromise is bounded.** A stolen passkey can't be exported from
  the device it's bound to. Even physical theft requires bypassing the
  device's biometric / PIN gate.

For technical members using CLI: they additionally hold a CLI
credential (substrate session token) for direct API access. CLI
credentials rotate on a schedule (initial: every 7 days; tightened
later if needed).

## Infrastructure on APOLLO

The substrate, IronClaw, and web UI all run on APOLLO. External
access via Cloudflare Tunnel (recommended) or direct port-forward
(simpler but exposes APOLLO's public IP).

| Service | Local port | Public route |
|---------|------------|--------------|
| ZP HTTP API | localhost:17010 | not exposed; IronClaw and web UI are local clients |
| ZP gRPC | localhost:17011 | not exposed; same reason |
| IronClaw web gateway | localhost:3000 | `foundation.zeropoint.global` via Cloudflare Tunnel |
| Auth/passkey endpoint | localhost:3000/auth | same |

TLS handled by Cloudflare's edge; APOLLO sees plaintext-from-tunnel.
DNS: `foundation.zeropoint.global` CNAME → Cloudflare → tunnel ID.

**APOLLO running 24/7 becomes a Foundation infrastructure
requirement.** Power outage on Ken's home network = Foundation
downtime. Mitigations:
- UPS on APOLLO (small, ~$200)
- Backups (already covered, task #91 item 2)
- Monitoring (task #91 item 5) — Ken should know within minutes if
  APOLLO goes down
- Migration plan: dedicated VPS (Hetzner, Vultr) or rented bare metal
  within 30 days of Foundation moving beyond pilot stage

For the v1 pilot phase (Ken + 2-3 initial members), APOLLO is sufficient.
For real Foundation operations beyond pilot, migrate to dedicated
infrastructure — but the architecture doesn't change, only the host.

## Onboarding ceremony

Operator-driven, captured as receipts:

1. Operator: `zp foundation invite alice --scope member-broad --expiry 365d`
   - Substrate emits `MEMBER_INVITATION` receipt
   - Returns one-time enrollment URL + token
2. Operator sends URL + token to new member via secure out-of-band
   channel (Signal, encrypted email)
3. New member visits URL in browser, enters token
4. WebAuthn enrollment ceremony: member's device generates a passkey,
   public key registered server-side
5. Substrate emits `MEMBER_ENROLLED` receipt — citing the invitation
   receipt + the new member's first passkey + their delegation
6. Member is now in. They open IronClaw, ask Foundation things in
   natural language, all governed.

The chain proves who invited whom, with what scope, when, and that the
member actually completed enrollment. Membership history is fully
auditable.

## Decommissioning

Reverse: `zp foundation revoke alice --reason "departed 2026-12-31"`.
Substrate emits `MEMBER_REVOCATION` receipt. All future actions by
alice are rejected. Her past chain entries remain valid evidence of
historical actions (signatures, decisions) but she can't take new ones.

If a member's *device* is lost (not the member departing), use
`zp foundation rotate-key alice`. Generates new enrollment token,
member re-enrolls. Old passkey is revoked but the member's identity
persists.

## Effects on prior architectural docs

- **AGENTIC-SURFACE-2026-05.md (II.14)**: unchanged. Substrate exposes
  gRPC verbs; agentic clients (IronClaw, future MCP-aware tools)
  consume them. The clients now happen to be hosted on Foundation
  infrastructure instead of personal machines, but the architecture is
  the same.

- **PUBLIC-PRIVATE-SEPARATION-2026-05.md**: unchanged conceptually.
  "Foundation-internal operational data" was always the private side;
  this doc just makes explicit that it's centralized on APOLLO. The
  three tiers (public / configuration templates / operational data)
  still apply.

- **SIGNATURES-2026-05.md (II.15)**: unchanged. Foundation document
  signing happens against the Foundation substrate; member signatures
  attest with member delegation keys; the chain proves who signed
  what.

- **L3 hardening (#91)**: backup script (#91 item 2) already covers
  Foundation operational state. Multi-tenant work IS this doc — task
  #91 item 3 is now superseded. Schema migration (#91 item 4) becomes
  more important because schema changes affect *everyone* in the
  Foundation, not just Ken. Monitoring (#91 item 5) becomes critical
  because APOLLO downtime affects all members.

## Next-week pilot scope

Honest about what ships:

| Component | By next week | After |
|-----------|--------------|-------|
| Substrate running on APOLLO with Foundation chain | ✓ already done | ongoing operations |
| Single-Ken Foundation Genesis | ✓ already done | quorum migration in 30-60 days |
| Cloudflare Tunnel + DNS | needs setup | enables remote access |
| Member type: technical CLI | possible (manual delegation) | continues |
| Member type: web/passkey | unlikely (infrastructure not built) | 2-4 weeks |
| Observer tier | not blocking; design ready | 30 days |
| Multi-tenant IronClaw config | needs verification | 1-2 weeks |
| Membership ceremony CLI | needs design + implementation | 1-2 weeks |
| Decommissioning flow | not blocking pilot | 30 days |

**Next-week onboarding is realistically limited to technical members
who can use CLI** + Ken provisions them directly (manual delegation
issuance + share enrollment token + member configures local CLI
against Foundation substrate URL).

Non-technical members wait until the web/passkey path ships
(2-4 weeks of focused infrastructure work after L3 hardening
stabilizes). That's an honest tradeoff: Foundation has working
governed substrate now, full membership UX in 4-6 weeks. The pilot
period is sufficient to validate the architecture; the wider rollout
follows.

## Future work (not v1, captured for visibility)

- **Quorum operations** for Foundation Genesis (M-of-N hardware
  wallets). Picks up the multi-signing infrastructure already drafted
  in CLAUDE.md. Target: 30-60 days from v1.
- **Federation between Foundations** via V.5 trust portability. When
  multiple ZP-governed organizations exist, they can compose trust
  without a central authority. Multi-year horizon.
- **Recovery from total Operator loss**: if Ken's Genesis key is
  lost entirely (lost mnemonic AND lost hardware), Foundation
  reconstitution requires the quorum to ratify a new Genesis. v1 has
  this gap; quorum closes it.
- **Member-private chain extensions**: each member optionally maintains
  a personal mini-chain for their own private receipts that don't go
  to Foundation chain (personal notes, individual delegations). Bridges
  the gap between fully-shared Foundation state and per-member privacy.
- **Foundation-as-counterparty trust**: when partners need to verify
  Foundation signatures, they verify against Foundation Genesis. The
  current Foundation public key gets published in a public registry
  (e.g., `zeropoint.global/keys`) and signed by hardware wallets.

## Status

Design ratified by Ken's three load-bearing decisions (APOLLO,
passkeys, single-Ken-then-hardware-quorum). Implementation work
captured as separate tasks. Pilot scope acknowledges what realistically
ships next week vs in the following weeks.

This document supersedes earlier multi-tenant thinking that assumed
federated-sovereign-individuals. The Foundation is an organization;
it runs the organizational-substrate pattern. ZP supports both
patterns and external adopters can choose differently.
