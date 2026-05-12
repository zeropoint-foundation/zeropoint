#!/usr/bin/env bash
# zp-backup.sh — back up ZeroPoint operational state.
#
# Backs up local sovereignty material to a timestamped directory:
#   - vault.json     (encrypted at rest; copy-as-bytes is safe)
#   - data/audit.db  (live SQLite, via .backup API to handle WAL mode)
#   - keys/          (signing keys — sovereignty material)
#   - genesis.json   (genesis record)
#   - session.json   (current session — included for completeness; regenerated on server restart)
#
# Produces a manifest.json with BLAKE3 (preferred) or SHA-256 hashes for
# each file, enabling integrity verification on restore.
#
# Restore drill: copy backup contents to ~/ZeroPoint/ on a fresh machine,
# run `zp doctor`, verify health. See docs/RESTORE-2026-05.md.
#
# Usage:
#   ./scripts/zp-backup.sh                   # backup to ~/ZeroPoint/backups/<timestamp>/
#   BACKUP_ROOT=/path/to/dest ./scripts/zp-backup.sh   # custom destination
#   ZP_HOME=/path/to/zp ./scripts/zp-backup.sh         # custom source
#
# Exit codes:
#   0 — backup completed successfully
#   1 — pre-flight check failed (missing ZP_HOME, etc.)
#   2 — sqlite3 not found (required for audit-DB backup)
#   3 — backup operation failed mid-run

set -euo pipefail

ZP_HOME="${ZP_HOME:-$HOME/ZeroPoint}"
BACKUP_ROOT="${BACKUP_ROOT:-$ZP_HOME/backups}"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_DIR="$BACKUP_ROOT/$TIMESTAMP"
MANIFEST="$BACKUP_DIR/manifest.json"

# ── Pre-flight checks ──────────────────────────────────────────────────

if [ ! -d "$ZP_HOME" ]; then
    echo "ERROR: ZP_HOME does not exist: $ZP_HOME" >&2
    echo "       Set ZP_HOME=... if your install is elsewhere." >&2
    exit 1
fi

if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "ERROR: sqlite3 not found on PATH." >&2
    echo "       Required for safe audit-DB backup (uses SQLite .backup API)." >&2
    echo "       Install: brew install sqlite (macOS) or apt-get install sqlite3 (Linux)" >&2
    exit 2
fi

mkdir -p "$BACKUP_DIR"
echo "ZeroPoint backup → $BACKUP_DIR"
echo

# ── Hash helper ────────────────────────────────────────────────────────
# Use BLAKE3 if available (matches substrate's canonical hash function),
# fall back to SHA-256.

hash_file() {
    local f="$1"
    if command -v b3sum >/dev/null 2>&1; then
        printf 'blake3:%s' "$(b3sum "$f" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        printf 'sha256:%s' "$(shasum -a 256 "$f" | awk '{print $1}')"
    elif command -v sha256sum >/dev/null 2>&1; then
        printf 'sha256:%s' "$(sha256sum "$f" | awk '{print $1}')"
    else
        printf 'no-hash-tool'
    fi
}

# ── Manifest helpers ───────────────────────────────────────────────────
# We build manifest.json incrementally. Entries are written to a temp
# file, then assembled into proper JSON at the end.

MANIFEST_ENTRIES="$BACKUP_DIR/.manifest_entries"
: > "$MANIFEST_ENTRIES"

record_entry() {
    local rel="$1"
    local hash="$2"
    local kind="$3"
    printf '    "%s": { "hash": "%s", "kind": "%s" }\n' "$rel" "$hash" "$kind" >> "$MANIFEST_ENTRIES"
}

# ── Backup operations ──────────────────────────────────────────────────

backup_file() {
    local src="$1"
    local label="$2"

    if [ ! -e "$src" ]; then
        echo "  ○ $label: NOT PRESENT (skipping)"
        return
    fi

    local rel="${src#$ZP_HOME/}"
    local dest="$BACKUP_DIR/$rel"
    mkdir -p "$(dirname "$dest")"
    cp "$src" "$dest"
    local hash=$(hash_file "$dest")
    record_entry "$rel" "$hash" "file"
    echo "  ✓ $label: $hash"
}

backup_dir() {
    local src="$1"
    local label="$2"

    if [ ! -d "$src" ]; then
        echo "  ○ $label: NOT PRESENT (skipping)"
        return
    fi

    local rel="${src#$ZP_HOME/}"
    local dest="$BACKUP_DIR/$rel"
    cp -R "$src" "$dest"

    # Hash each file in the directory, record as collection
    local count=0
    while IFS= read -r f; do
        local relfile="${f#$BACKUP_DIR/}"
        local h=$(hash_file "$f")
        record_entry "$relfile" "$h" "dir-file"
        count=$((count + 1))
    done < <(find "$dest" -type f)

    echo "  ✓ $label: directory copied ($count files)"
}

backup_sqlite() {
    local src="$1"
    local label="$2"

    if [ ! -f "$src" ]; then
        echo "  ○ $label: NOT PRESENT (skipping)"
        return
    fi

    local rel="${src#$ZP_HOME/}"
    local dest="$BACKUP_DIR/$rel"
    mkdir -p "$(dirname "$dest")"

    # Use SQLite's .backup API — safe for live DBs in WAL mode.
    # This produces a fully-self-contained backup with no -shm/-wal needed.
    if ! sqlite3 "$src" ".backup '$dest'"; then
        echo "  ✗ $label: sqlite3 .backup FAILED" >&2
        exit 3
    fi
    local hash=$(hash_file "$dest")
    record_entry "$rel" "$hash" "sqlite-backup"
    echo "  ✓ $label (sqlite .backup): $hash"
}

# ── Backup the operational state ───────────────────────────────────────

echo "Backing up:"
backup_file   "$ZP_HOME/vault.json"        "vault"
backup_sqlite "$ZP_HOME/data/audit.db"     "audit chain"
backup_dir    "$ZP_HOME/keys"              "signing keys"
backup_file   "$ZP_HOME/genesis.json"      "genesis"
backup_file   "$ZP_HOME/session.json"      "session"
echo

# ── Assemble manifest.json ─────────────────────────────────────────────

{
    echo '{'
    printf '  "timestamp": "%s",\n' "$TIMESTAMP"
    printf '  "source_zp_home": "%s",\n' "$ZP_HOME"
    printf '  "hostname": "%s",\n' "$(hostname)"
    printf '  "user": "%s",\n' "$(whoami)"
    printf '  "backup_tool": "zp-backup.sh",\n'
    printf '  "backup_tool_version": "1.0",\n'
    printf '  "files": {\n'
    # Insert entries with commas between, no trailing comma
    awk 'NR>1 {print prev","} {prev=$0} END {print prev}' "$MANIFEST_ENTRIES"
    printf '  }\n'
    echo '}'
} > "$MANIFEST"

rm -f "$MANIFEST_ENTRIES"

# ── Summary ────────────────────────────────────────────────────────────

BACKUP_SIZE=$(du -sh "$BACKUP_DIR" 2>/dev/null | awk '{print $1}')

echo "──────────────────────────────────────────────────"
echo "✓ Backup complete"
echo "  Location: $BACKUP_DIR"
echo "  Size:     $BACKUP_SIZE"
echo "  Manifest: $MANIFEST"
echo
echo "To verify integrity:"
echo "  cat $MANIFEST"
echo
echo "To restore on a fresh machine:"
echo "  See docs/RESTORE-2026-05.md"
echo "──────────────────────────────────────────────────"
