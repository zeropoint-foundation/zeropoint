# Audit chain operator runbook

**Audience:** Operators running `zp-server` in production or investigating
a suspected audit chain incident.
**Prereqs:** Shell access to the host running `zp-server`, read access to
`~/.zeropoint/data/audit.db`, and the `zp` CLI on `PATH`.
**Reference:** `docs/audit-architecture.md` for the canonical schema,
invariants, and back doors. `docs/audit-invariant.md` for the formal
verification rules P1–P4.

## 1. What "normal" looks like

On a healthy system:

- `audit.db` exists at `~/.zeropoint/data/audit.db` (or the path given
  by `ZP_AUDIT_DB` / the server config). File is non-zero, WAL sidecar
  (`audit.db-wal`) present.
- `PRAGMA user_version` returns `2` (Stage 4 schema).
- `sqlite3 audit.db 'SELECT COUNT(*) FROM audit_entries'` returns a
  monotonically increasing number over time.
- Server logs contain `Audit store initialized (schema v2)` on startup
  and `Appended audit entry: <ULID>` for each governance-relevant action.
- `zp audit verify` (or the admin HTTP endpoint) returns ACCEPT with
  zero violations.

If any of the above is false, consult §3 or §4.

## 2. Inspecting the chain

### 2.1 Dump the chain head

```
sqlite3 ~/.zeropoint/data/audit.db \
  'SELECT id, timestamp, substr(prev_hash,1,16), substr(entry_hash,1,16), policy_module
   FROM audit_entries ORDER BY rowid DESC LIMIT 20;'
```

### 2.2 Verify end-to-end

```
zp audit verify
```

This runs the catalog verifier, which checks rules P1 (genesis), P2
(entry hash recomputation — strict, post-AUDIT-03), P3 (chain linkage),
and P4 (signatures where present). Any violation is printed with the
offending entry id.

### 2.3 Look for a fork

The Stage 4 schema has a partial `UNIQUE` index on `prev_hash` (excluding
genesis) called `idx_unique_prev_hash`. A fork at the storage layer is
impossible unless a writer bypassed the `append` code path. To check:

```
sqlite3 ~/.zeropoint/data/audit.db <<'SQL'
SELECT prev_hash, COUNT(*) AS n
FROM audit_entries
WHERE prev_hash != (SELECT substr(hex(randomblob(32)),1,64))  -- any non-genesis
GROUP BY prev_hash
HAVING n > 1;
SQL
```

A non-empty result means the chain forked. This should be physically
impossible; if you see it, **preserve the DB and escalate immediately**
(see §4).

## 3. Common incidents

### 3.1 "audit DB schema version mismatch"

**Symptom:** `zp-server` fails to boot with
`StoreError::SchemaMismatch { found: <N>, expected: 2 }`.

**Cause:** The `audit.db` at the configured path was stamped with a
different `user_version` — either a v1 database from before the Stage 4
recanonicalization, or (rarely) a future version from a newer build.

**Resolution:**

1. **Do not delete the file yet.** It is forensic evidence.
2. Preserve it:
   ```
   bash security/pentest-2026-04-06/forensic-dump-audit-03.sh ~/.zeropoint/data/audit.db
   ```
   This emits a sibling `.forensic.tar.gz` with the DB, WAL, shm, and a
   `PRAGMA integrity_check` dump.
3. Move the old DB aside:
   ```
   mv ~/.zeropoint/data/audit.db ~/.zeropoint/data/audit.db.v1.preserved
   mv ~/.zeropoint/data/audit.db-wal ~/.zeropoint/data/audit.db-wal.v1.preserved 2>/dev/null || true
   mv ~/.zeropoint/data/audit.db-shm ~/.zeropoint/data/audit.db-shm.v1.preserved 2>/dev/null || true
   ```
4. Restart `zp-server`. It will create a fresh v2 database.
5. If the old DB is needed for historical investigation, open it with a
   standalone `sqlite3` session — do **not** feed it back to `zp-server`.

### 3.2 Zero-byte `audit.db`

**Symptom:** The file exists but is 0 bytes, and `sqlite3 ... 'SELECT ...'`
returns `Error: no such table: audit_entries`.

**Cause:** A previous boot created the file but never ran `init()`, or
the file was touched externally (`touch`, a broken restore, etc.).

**Resolution:** Preserve with `forensic-dump-audit-03.sh` (even a zero-byte
file is evidence), delete, restart. This is expected to be rare after
Stage 4; if you see it under normal operation, file a bug.

### 3.3 `verify_with_catalog` returns violations

**Symptom:** `zp audit verify` reports one or more violations.

**Cause:** Either a real integrity issue (tamper, bit rot, partial write)
or a code bug that landed a bad preimage (the AUDIT-02 class of bug).

**Resolution:**

1. Capture the report — save the full output.
2. Identify the first offending entry (by rowid, not timestamp).
3. Check `policy_module` and `actor` on the row — does it correspond to
   a known legitimate action?
4. Preserve and escalate. Do **not** run `tamper_entry_hash` or any
   "repair" — the violation is diagnostic information.
5. If the build has the `pentest-demo` feature disabled (it should in
   production), there is no supported in-place recovery. Investigation
   proceeds from a preserved forensic dump.

### 3.4 Address already in use on :3000

**Symptom:** Server fails to start with `Address already in use (os error 48)`.

**Cause:** A prior `zp-server` process is still bound to the port.

**Resolution:**
```
lsof -ti :3000 | xargs kill
```
Then restart. If the process keeps returning, check your process
supervisor — ZeroPoint does not self-respawn.

### 3.5 SQLITE_CONSTRAINT_UNIQUE on `idx_unique_prev_hash`

**Symptom:** A log line `SqliteFailure(Error { code: ConstraintViolation,
extended_code: 2067 }, ...)` involving `audit_entries`.

**Cause:** Something attempted to insert a second row with a
`prev_hash` that already exists in the chain. The Stage 4 partial unique
index rejected it. The legitimate `append` path **cannot produce this**
because `BEGIN IMMEDIATE` serializes writers; the only way to see it is
a side-channel writer (a bug, a migration script, or a malicious dump).

**Resolution:**

1. Treat as a P1 incident. The chain is still consistent (the insert
   was rejected) but something tried to fork it.
2. Capture the full log line including the entry's attempted id.
3. Preserve the DB with `forensic-dump-audit-03.sh`.
4. Investigate what code path produced the insert. Grep for raw
   `INSERT INTO audit_entries` outside `crates/zp-audit/src/store.rs` —
   there should be zero hits.

## 4. Escalation

Any of the following is a P1 incident:

- Chain verification fails outside of a test environment.
- `idx_unique_prev_hash` fires in production logs.
- `audit.db` is unexpectedly truncated, missing, or schema-mismatched.
- `tamper_entry_hash` is seen in logs on a build that should not have
  the `pentest-demo` feature enabled.

Escalation procedure:

1. Do **not** attempt in-place repair.
2. Stop `zp-server` cleanly (`SIGTERM`, not `SIGKILL`, so the WAL is
   checkpointed).
3. Run `forensic-dump-audit-03.sh` and preserve the archive off-box.
4. Capture the last 500 lines of `zp-server` logs.
5. Open an incident ticket with the preserved dump, logs, and the
   output of `zp audit verify` (even if it fails).
6. Do not restart `zp-server` on the same DB until the incident is
   triaged.

## 5. What NOT to do

- Do not run `VACUUM` or `REINDEX` on `audit.db`. These rewrite rows
  and obliterate the integrity signal.
- Do not manually edit rows with `sqlite3`. Every edit invalidates at
  least one `entry_hash` and cascades through the chain.
- Do not copy `audit.db` without also copying `audit.db-wal` and
  `audit.db-shm`. Partial copies leave the DB inconsistent.
- Do not enable the `pentest-demo` feature in a production build. The
  `tamper_entry_hash` and `restore_entry_hash` back doors exist solely
  for the integrity demo and are dangerous outside that context.
- Do not trust a timestamp-ordered export. The chain is ordered by
  `rowid` (insertion), not by `timestamp` — sub-millisecond ties were
  part of the AUDIT-03 failure mode.

## 6. References

- Canonical schema and invariants: `docs/audit-architecture.md`
- Formal verification rules: `docs/audit-invariant.md`
- AUDIT-03 recanonicalization history: `docs/audit-architecture.md` §10
- Forensic dump tool: `security/pentest-2026-04-06/forensic-dump-audit-03.sh`
- Mesh inbound authentication (in-progress): `docs/rfc-mesh-inbound-auth-v1.md`
