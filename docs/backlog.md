# Backlog — RESOLVED

All items from the ARTEMIS relay cycle (020–026) have been addressed.
Original items preserved below with resolution notes.

Last updated: 2026-04-16.

---

## 1. Ironclaw DATABASE_URL preflight UX

**Origin:** Relay 035, issue 1.
**Status:** Done.

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
**Status:** N/A — scripts do not exist in the repo.

The `tools/audit/` directory with CSP-related scripts was referenced in
the original finding but these scripts were never committed to the repo.
If CSP audit scripts are added in the future, they should use `grep -E`
(portable extended regex) instead of `grep -P` (GNU-only Perl regex).

---

## 3. Credential conflict UX

**Origin:** Relay 030.
**Status:** Done.

The vault_store handler now checks `vault.list()` before storing to
detect if a credential already exists for the given vault_ref. The
response event includes a `replaced: true/false` field. The frontend
shows "✓ Updated" instead of "✓" when replacing, and re-enables the
input after 3 seconds so the operator can update again. The stored
count is only incremented for genuinely new credentials.

---

## 4. Rotation runbook + CLI command

**Origin:** Backlog (pre-relay).
**Status:** Done.

The canon permission enforcement error message in `lib.rs` references a
"rotation runbook" that didn't exist. Now written at
`docs/key-rotation-runbook.md`. The `zp keys rotate` CLI command is
implemented, supporting both operator rotation (`--target operator`) and
agent rotation (`--target <agent-name>`). Rotation certificates are
persisted to `~/.zeropoint/keys/rotations.json` with parent co-signing
for defense-in-depth.

---

## 5. `zp keys list` — cert vs secret distinction

**Origin:** Relay cycle observation.
**Status:** Done.

`zp keys list` now shows four-state status for both genesis and
operator keys: "cert + secret", "cert only (secret missing — run
`zp recover`)", "secret only (cert missing)", or "missing". Uses the
existing `KeyringStatus` fields (`has_genesis_secret`,
`has_operator_secret`). Also shows the rotation chain certificate
count if `rotations.json` exists.

---

## Resolution summary

All five items resolved in the hardening cycle:

1. **Preflight UX** — actionable remediation guidance per env var type
2. **BSD grep** — scripts never materialized; noted for future work
3. **Credential conflict** — replaced/new distinction in UI + backend
4. **Rotation runbook + CLI** — `zp keys rotate` shipped, docs updated
5. **Keys list** — cert/secret distinction with recovery guidance

Backlog is clear for the next pentest cycle.
