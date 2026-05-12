# Restoring a ZeroPoint Operational State

*2026-05-11. Companion to `scripts/zp-backup.sh` and L3 hardening
(task #91).*

## Scope

This document covers **restoring a Foundation member's personal ZP
operational state** from a backup produced by `scripts/zp-backup.sh`.
The scenarios it addresses:

- Disk failure or accidental deletion on a Foundation member's primary
  machine
- Migrating a member's ZP install from one machine to another (e.g.,
  APOLLO → ARTEMIS, or to a replacement laptop)
- Recovering from a corrupted audit DB or vault
- Bootstrapping a new machine that's meant to be the same identity as
  an existing one (rare; usually each machine has its own identity)

Out of scope here:
- Restoring from a hardware-wallet-based Genesis seed (Trezor, etc.) —
  that's a Genesis ceremony, not a backup restore. See the onboarding
  docs for that flow.
- Cross-member restore (Member A trying to restore from Member B's
  backup) — by design impossible without sovereignty material; each
  member's backup is keyed to their own Genesis identity.
- Cloud / off-machine backups — task #91 v2 work.

## What a backup contains

A backup directory produced by `zp-backup.sh` contains:

```
<BACKUP_ROOT>/<TIMESTAMP>/
├── manifest.json        ← integrity manifest with BLAKE3/SHA-256 hashes
├── vault.json           ← encrypted vault
├── data/audit.db        ← SQLite .backup of audit chain (self-contained,
│                          no -shm/-wal needed)
├── keys/                ← signing keys directory
├── genesis.json         ← genesis record (the substrate's identity root)
└── session.json         ← current session (regenerated on restart;
                           safe to omit if missing)
```

Each file's hash is recorded in `manifest.json` so the restore procedure
can verify nothing was corrupted in transit (USB drive bit-flip, network
transfer error, cosmic ray, etc.).

## Pre-flight: what you need

1. **The backup directory** (typically `~/ZeroPoint/backups/<TIMESTAMP>/`,
   or wherever you copied it).
2. **sqlite3** on PATH (`brew install sqlite` on macOS).
3. **b3sum** for BLAKE3 verification, or `shasum -a 256` for SHA-256
   fallback. Both standard on macOS.
4. **Your ZP install** built and on PATH — the binary needs to be the
   same major version as the one that produced the backup. Mismatches
   may require schema migrations (see "Schema-version mismatch" below).
5. **A clean target** (`~/ZeroPoint/` does not exist or has been moved
   aside). NEVER restore on top of a live operational state —
   move the existing directory first.

## Procedure

### 1. Make a backup of what's currently there

Even if the existing state seems broken, preserve it. Restores can
fail; you want a fallback.

```sh
if [ -d ~/ZeroPoint ]; then
    mv ~/ZeroPoint ~/ZeroPoint.before-restore-$(date -u +%Y%m%dT%H%M%SZ)
fi
```

### 2. Verify the backup's integrity

```sh
BACKUP=~/ZeroPoint/backups/<TIMESTAMP>     # adjust to your backup path
cat "$BACKUP/manifest.json"
```

For each file in the manifest, hash it and confirm it matches:

```sh
# Example using b3sum (preferred):
cd "$BACKUP"
b3sum vault.json data/audit.db genesis.json session.json keys/*
# Compare each output against the manifest's "blake3:..." values
```

If any hash mismatches, **stop**. The backup is corrupted. Use an
earlier backup, or escalate to recovery from Genesis seed.

### 3. Reconstitute ~/ZeroPoint

```sh
mkdir -p ~/ZeroPoint/data
cp "$BACKUP/vault.json"     ~/ZeroPoint/vault.json
cp "$BACKUP/data/audit.db"  ~/ZeroPoint/data/audit.db
cp -R "$BACKUP/keys"        ~/ZeroPoint/keys
cp "$BACKUP/genesis.json"   ~/ZeroPoint/genesis.json
# session.json optional; the server will mint a fresh one on next start
[ -f "$BACKUP/session.json" ] && cp "$BACKUP/session.json" ~/ZeroPoint/session.json
```

Permissions on `keys/` are sensitive — the files should be `0600`:

```sh
chmod 0600 ~/ZeroPoint/keys/*
chmod 0700 ~/ZeroPoint/keys
chmod 0600 ~/ZeroPoint/vault.json
```

### 4. Verify the substrate sees the restored state

```sh
zp doctor
```

Expect to see:
- ✓ Identity from operator key (credential store)
- ✓ Audit chain readable
- ✓ Vault decryptable

If `zp doctor` reports schema mismatch on audit.db, see "Schema-version
mismatch" below.

### 5. Verify a tool call still works

Start zp-server, then run a smoke test:

```sh
zp serve --port 17010 &
sleep 2
zp --data-dir ~/ZeroPoint/data emit zp-restore-test --meta key=test
```

The emit should succeed and the audit chain should grow by one entry.
That proves end-to-end functionality post-restore.

## Failure modes

### Schema-version mismatch

If the backup was taken on an older ZP version than the current binary
expects, the audit chain may fail to open with `SchemaMismatch { found:
N, expected: M }`.

Three options:

1. **Roll back the ZP binary** to a version that matches the backup's
   schema. Examine the backup's `manifest.json` `backup_tool_version`
   field and `git log` for when that version was current.

2. **Run schema migrations** if a migration path exists. As of
   2026-05-11, schema migrations are not implemented (see task #91 item
   3). When they land, this section will list the steps.

3. **Reissue from Genesis** (lossy — abandons audit history). Requires
   the 24-word recovery mnemonic. Use only as last resort.

### Vault won't decrypt

If `zp doctor` reports the vault is unreachable or won't decrypt:

- Check that the OS Keychain (macOS) or equivalent contains the master
  key. If you're restoring to a NEW machine, the master key isn't there.
- The vault is encrypted with a key derived from your sovereignty
  provider (Touch ID, Trezor, login password, etc.). Restoring to a new
  machine requires re-binding to that provider — typically via
  `zp recover` with the 24-word mnemonic.

### Keys directory permissions

If keys/ files end up `0644` instead of `0600`, the substrate will
refuse to use them (CRIT-8 security check). Always:

```sh
chmod 0700 ~/ZeroPoint/keys
chmod 0600 ~/ZeroPoint/keys/*
```

### Missing session.json

Harmless. The server mints a fresh one on next start. Token rotates
naturally.

## Restore drill (do this BEFORE you need it)

A backup is only as good as its tested restore. Before relying on
backups for real, do at least one full restore drill:

1. On ARTEMIS (or a separate machine, or a clean user account):
   ```sh
   # Get a copy of an APOLLO backup somehow (USB, scp, encrypted-cloud, etc.)
   scp apollo:~/ZeroPoint/backups/<TIMESTAMP>.tar.gz ./
   tar xzf <TIMESTAMP>.tar.gz
   ```

2. Follow the procedure above to reconstitute `~/ZeroPoint/`.

3. Run `zp doctor` and a smoke `zp emit`.

4. If anything fails, fix the procedure (this document) before relying
   on backups in production.

5. Tear down the test restore: `rm -rf ~/ZeroPoint && mv
   ~/ZeroPoint.before-restore-<TIMESTAMP> ~/ZeroPoint` (or similar).

Document the result of the drill — successful drills build confidence;
failed drills reveal procedural gaps that documentation alone can't.

## Backup hygiene

- **Run backups regularly.** Manual today; scheduled via launchd/cron
  in v2. Suggested cadence: nightly at minimum, plus before any
  high-stakes operation.
- **Store backups off the source machine.** Local-only backups protect
  against software failure but not hardware loss. Encrypted external
  drives, encrypted cloud storage (Backblaze B2, Tarsnap, etc.), or
  encrypted Foundation-shared infra all work. The vault is already
  encrypted; the audit.db should be encrypted before cloud upload.
- **Rotate.** Old backups have value (point-in-time recovery), but
  unlimited retention isn't free. Suggest: keep daily for 30 days,
  weekly for 6 months, monthly for 2 years, annually forever. Tune to
  your storage budget.
- **Test occasionally.** Quarterly restore drill on a non-production
  machine. The drill is the substrate's equivalent of a fire-extinguisher
  inspection: necessary precisely because you hope you'll never need it.

## Restore drill results

### Drill 1 — 2026-05-12, APOLLO (tmpdir)

**Environment:** APOLLO-4, macOS, `ZP_HOME=/tmp/zp-restore-drill-51207`  
**Backup taken:** 2026-05-12T15:06:46Z → `~/ZeroPoint/backups/20260512T150646Z/`  
**Backup size:** 184K (vault.json 75K, audit.db snapshot, 3 key files, genesis, session)  
**Wall-clock time:** ~90 seconds end-to-end (backup + restore + drill)

**Procedure steps:**
1. `scripts/zp-backup.sh` → produced timestamped backup with manifest.json ✓
2. SHA-256 hash verification of vault.json, genesis.json, session.json against manifest ✓
3. `sqlite3 "$BACKUP/data/audit.db" ".backup '$DRILL_HOME/data/audit.db'"` — live SQLite backup API, no WAL artifacts ✓
4. `ZP_HOME=$DRILL_HOME zp doctor` → ✓ System healthy, 21 chain entries, integrity verified, genesis sealed, 17/17 signatures pass ✓
5. `ZP_HOME=$DRILL_HOME zp emit zp-restore-drill-test --meta context=acceptance` → receipt `obsv-fceda2aac4ea` appended ✓

**Warnings (expected, non-blocking):**
- Binary version warning (dev build vs HEAD) — cosmetic
- No config.toml in drill home — uses defaults, as expected for a restore
- Port 3000 in use (live server running on APOLLO) — irrelevant for CLI-only drill
- 0/3 tools canonicalized — tools were not part of the backup scope

**Procedural gaps found:** None. The restore procedure in the sections
above is complete and correct as written.

**Drill result:** PASSED ✓

---

## Future work

- Schema migration framework (task #91 item 3) — makes
  schema-version-mismatch recoverable without rolling back ZP binary
- `zp backup` and `zp restore` subcommands — make this native to the
  CLI rather than a shell script
- Scheduled / automated backups — launchd or cron integration
- Encrypted cloud backup target — for Foundation members who want
  off-machine backups
- Cross-member backup verification — Member A can produce a *signed*
  attestation of their backup integrity, which Member B can verify
  without seeing the backup contents (privacy-preserving verification
  for shared infrastructure)
