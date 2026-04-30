# Production Genesis Checklist

*Pre-flight items that MUST be addressed before promoting a ZeroPoint*
*deployment from dev to production. The chain is append-only and signed —*
*these items are dangerous to defer until after first production write.*

---

## Chain hygiene

- [ ] **Purge the dev chain** (`~/ZeroPoint/data/audit.db`) before production
  genesis. Dev chains accumulate test data, exploratory canonicalizations,
  and (historically) credential material from early code revisions that
  predated current filtering. Cf. issue #193 — entry `0e68141d5b93`
  contained a plaintext Anthropic API key from a prior code path; the
  current code at `lib.rs:3515-3552` filters correctly but the historical
  beads are signed and immutable. Production genesis must start from a
  clean DB.

- [ ] **Re-canonicalize all providers and tools** against the clean chain.
  Bead-zeros for the new chain must be emitted by the production-grade
  canonicalization code (with `debug_assert!` guards from #193 active).
  The existing `tool_chain::emit_canonicalization_receipt` is idempotent —
  running it on a clean DB recreates the bead-zero set without manual
  intervention.

- [ ] **Rotate any credential** that may have appeared in a dev-chain bead.
  `grep -E "sk-[A-Za-z0-9_-]{20,}" ~/ZeroPoint/data/audit.db` against the
  pre-purge dev chain. Anything matching: rotate the corresponding upstream
  key (Anthropic, OpenAI, etc.) before production genesis. The dev chain's
  signature seals the leak — purging removes the file but not the prior
  exposure window.

## Identity & sovereignty

- [ ] Genesis ceremony performed under production sovereignty mode (Touch ID
  Secure Enclave, Trezor with passphrase, or hardware quorum) — not file-
  based or login-password.

- [ ] 24-word recovery mnemonic stored in operator-controlled offline
  storage. Tested via `zp recover --dry-run` against a fresh data dir.

- [ ] Operator key fingerprint (`zp keys list`) recorded in deployment doc;
  matches the public key embedded in the production genesis bead-zero.

## Substrate hardening (pre-Layer-3 prerequisites)

See `docs/future-work/cognitive-accountability.md` for the Layer 3
prereq list. Items relevant to production genesis specifically:

- [ ] Audit chain has been adversarially tested under hostile conditions
  (not just tamper-evident in the happy path).

- [ ] Sovereignty providers stable across v0.2 implementations (Touch ID
  Secure Enclave, Trezor passphrase, Windows Hello WinRT).

- [ ] ZP Guard allowlist tuned — `zp guard -s "ls"` < 50ms in the production
  environment. `docs/GUARD-SAFE-RENABLE.md` has the validation procedure.

- [ ] Multi-signing / quorum architecture designed (even if not implemented
  in v1, the `QuorumProvider` trait extension and per-device enrollment
  layout must anticipate it).

## Configuration

- [ ] `port` set explicitly via `zp config set port <port>` (don't rely on
  the default 3000 in production — collides with common dev services).

- [ ] `RUST_LOG` set to `info` minimum in production env. Debug-level
  observability via `zp tools log` is gated by tracing config.

- [ ] Network exposure decision made: `127.0.0.1` (localhost-only, default)
  or external bind (requires TLS termination — not handled by zp-server).

## Observability

- [ ] `zp doctor` returns zero failures, warnings reviewed and either
  resolved or explicitly accepted.

- [ ] `zp verify` returns ACCEPT against the production chain on every node
  in the fleet.

- [ ] At least one external monitoring point configured (cron job running
  `zp verify` weekly, alerting on non-zero exit).

---

*Add to this list as production-readiness gaps surface. The cost of a*
*missed item is low if caught here; high if discovered after first*
*production receipt is signed.*
