# Open backlog

Items identified during the ARTEMIS relay cycle (020–025) that are
deferred — none are security-critical, all are UX or operational polish.
Intended to be picked up before or in parallel with the next full pentest.

Last updated: 2026-04-16.

---

## 1. Ironclaw DATABASE_URL preflight UX

**Origin:** Relay 035, issue 1.
**Status:** Open.

When `DATABASE_URL` is unset or points to a nonexistent database, the
ironclaw integration panics deep in the connection pool. The user sees
a raw Rust backtrace instead of a helpful error.

**Fix:** Add a preflight check in the ironclaw startup path that
validates `DATABASE_URL` is set, the host is reachable, and the
database exists. Surface a clear error message with remediation steps
(set the env var, check the connection string, ensure the database
server is running).

**Files:** `crates/zp-server/src/ironclaw/` (startup/init path).

---

## 2. BSD grep in CSP audit scripts

**Origin:** Relay 034.
**Status:** Open.

The CSP audit scripts in `tools/` use GNU grep flags (`-P` for
Perl-compatible regex) that don't exist on macOS BSD grep. The scripts
work in CI (Linux) but fail silently or with errors on developer
machines.

**Fix:** Replace `grep -P` with `grep -E` (extended regex, portable)
or use `sed`/`awk` for the patterns that need lookahead/lookbehind.
Alternatively, detect the grep flavor and adapt.

**Files:** `tools/audit/` — CSP-related scripts.

---

## 3. Credential conflict UX

**Origin:** Relay 030.
**Status:** Open.

When the vault already contains a credential for a given provider and
the user tries to store a new one, the behavior is unclear. The store
succeeds silently (overwrite), but the user gets no confirmation of
what happened — no "replacing existing credential for X" message.

**Fix:** Before overwriting, check if the key exists in the vault. If
so, show a confirmation prompt in the onboard UI ("Replace existing
credential for OpenAI?") and a clear success message after. In the CLI
path, print a warning.

**Files:** `crates/zp-server/src/onboard/` (vault_store handler),
`crates/zp-server/assets/onboard.js` (UI feedback).

---

## 4. Rotation runbook documentation

**Origin:** Backlog (pre-relay).
**Status:** Done — `docs/key-rotation-runbook.md`.

The canon permission enforcement error message in `lib.rs` references a
"rotation runbook" that didn't exist. Now written. The runbook documents
the key hierarchy, recovery procedure, manual operator rotation, vault
key implications, and emergency procedures.

**Remaining gap:** The runbook documents manual rotation because `zp
rotate` is not yet implemented. When the CLI command ships, update the
runbook to reference it.

---

## 5. `zp keys list` — cert vs secret distinction

**Origin:** Relay cycle observation.
**Status:** Open.

`zp keys list` (or whatever command displays key status) should clearly
distinguish between:

- Certificate on disk (public key, issuer chain, expiry)
- Secret in credential store (present/absent, last-accessed if available)
- Secret in encrypted file (present/absent)

Currently the output doesn't make it obvious whether the *secret* is
available or just the certificate. This matters for recovery triage —
an operator needs to know "do I have the secret or just the cert?"
before deciding whether `zp recover` is needed.

**Fix:** Update the keys list output to show a status column:
`[cert+secret]`, `[cert only]`, `[secret only]` (shouldn't happen but
handle it). Query the credential store status without loading the actual
secret.

**Files:** `crates/zp-cli/src/` (keys subcommand, may need creation),
`crates/zp-keys/src/keyring.rs` (`KeyringStatus` struct already has
`has_genesis_secret`).

---

## Priority guidance

None of these block a pentest. If prioritizing:

1. **Credential conflict UX** (#3) — most user-facing, easiest to hit
   during normal onboarding.
2. **`zp keys list` distinction** (#5) — important for operator
   situational awareness during incidents.
3. **Ironclaw preflight** (#1) — only matters if ironclaw integration
   is active.
4. **BSD grep** (#2) — only affects developers on macOS running audit
   scripts locally.
5. **Rotation runbook update** (#4) — blocked on `zp rotate` implementation.
