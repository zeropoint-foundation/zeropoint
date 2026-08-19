#!/usr/bin/env python3
"""Reconcile what the Cartographer says it processed against what it recorded.

`run_catchup` continues past a failed entry and lets subsequent entries
advance the high-water mark. The code says so plainly:

    "failed entry stays unprocessed but subsequent entries advance the HWM
     (which will look like the failed one was processed). Acceptable for P3."

That is a reasonable trade in steady state. It is least reasonable on the
first catchup, which walks the entire historical chain -- every schema
vintage the substrate has ever written -- and is exactly the run where a
systematic failure would be absorbed at scale while the HWM marches on. The
failures exist only as scattered log lines, and the log rotates.

This does not need the log. Three independent records of "what was processed"
exist and can be compared:

  1. meta.last_processed_sequence  -- what the Cartographer claims
  2. object_receipts               -- one row per entry it actually linked;
                                      both branches of process_entry call
                                      link_receipt, so this is one-per-entry
  3. payload receipt_refs          -- what the trajectory payloads say

The gap between (1) and (2) IS the silently-skipped set. The gap between (2)
and (3) is a different and more interesting bug: a link written without the
payload update that should accompany it, or the reverse -- the derived view
disagreeing with itself.

Read-only. Opens both databases in immutable mode so it is safe to run
against a live substrate.

    python3 tools/ontology-check/catchup_reconcile.py
    python3 tools/ontology-check/catchup_reconcile.py --json
"""
import argparse, json, os, pathlib, sqlite3, sys


def ro(path):
    """Open read-only, and do not create the file if it is missing."""
    if not pathlib.Path(path).exists():
        return None
    return sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)


def scalar(conn, sql, default=0):
    try:
        row = conn.execute(sql).fetchone()
        return row[0] if row and row[0] is not None else default
    except sqlite3.Error:
        return default


def reconcile(ontology_path, audit_path):
    o = ro(ontology_path)
    if o is None:
        return {"error": f"no ontology database at {ontology_path} — "
                         "the Cartographer has never run, or ZP_CARTOGRAPHER_ENABLED is unset"}

    hwm = scalar(o, "SELECT CAST(value AS INTEGER) FROM meta "
                    "WHERE key = 'last_processed_sequence'")
    last_at = scalar(o, "SELECT value FROM meta WHERE key = 'last_processed_at'", None)
    linked = scalar(o, "SELECT COUNT(DISTINCT audit_id) FROM object_receipts")
    link_rows = scalar(o, "SELECT COUNT(*) FROM object_receipts")
    trajectories = scalar(o, "SELECT COUNT(*) FROM objects WHERE object_type = 'trajectory'")
    relationships = scalar(o, "SELECT COUNT(*) FROM relationships")

    # receipt_refs live inside the JSON payload blob. json_each is available in
    # SQLite 3.38+; fall back to counting in Python if the build lacks JSON1.
    try:
        refs = scalar(o, "SELECT SUM(json_array_length(payload, '$.receipt_refs')) "
                         "FROM objects WHERE object_type = 'trajectory'")
        refs_method = "json1"
    except sqlite3.Error:
        refs = 0
        for (blob,) in o.execute("SELECT payload FROM objects WHERE object_type='trajectory'"):
            try:
                refs += len(json.loads(blob).get("receipt_refs", []))
            except Exception:
                pass
        refs_method = "python"

    # largest trajectory, to check the cadence cap actually held
    biggest = 0
    try:
        biggest = scalar(o, "SELECT MAX(json_array_length(payload, '$.receipt_refs')) "
                            "FROM objects WHERE object_type='trajectory'")
    except sqlite3.Error:
        pass
    o.close()

    chain_entries = None
    a = ro(audit_path)
    if a is not None:
        # audit_entries is the chain table (zp-audit/src/store.rs:393). The
        # alternatives are tried anyway rather than asserted: this script must
        # degrade to "chain size unknown" rather than fail, since every other
        # number it reports is useful without it.
        for sql in ("SELECT MAX(rowid) FROM audit_entries",
                    "SELECT MAX(rowid) FROM audit_log",
                    "SELECT MAX(rowid) FROM entries"):
            v = scalar(a, sql, None)
            if v:
                chain_entries = v
                break
        a.close()

    out = {
        "hwm_claims_processed": hwm,
        "last_processed_at": last_at,
        "entries_linked": linked,
        "link_rows": link_rows,
        "payload_receipt_refs": refs,
        "refs_method": refs_method,
        "trajectories": trajectories,
        "relationships": relationships,
        "largest_trajectory": biggest,
        "chain_entries": chain_entries,
    }
    out["silently_skipped"] = max(hwm - linked, 0) if hwm else 0
    out["view_disagrees_with_itself"] = linked - refs
    out["chain_remaining"] = (chain_entries - hwm) if chain_entries and hwm else None
    return out


def main():
    home = pathlib.Path(os.path.expanduser("~"))
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default=str(home / ".zeropoint"),
                    help="directory holding ontology.db and audit.db")
    ap.add_argument("--ontology", default=None)
    ap.add_argument("--audit", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    d = pathlib.Path(args.data_dir)
    r = reconcile(args.ontology or d / "ontology.db", args.audit or d / "audit.db")

    if args.json:
        print(json.dumps(r, indent=2))
        return 0 if not r.get("error") and not r.get("silently_skipped") else 1

    if "error" in r:
        print(r["error"])
        return 2

    print("Cartographer catchup reconciliation")
    print(f"  HWM claims processed      {r['hwm_claims_processed']:>8,}")
    print(f"  entries actually linked   {r['entries_linked']:>8,}")
    print(f"  payload receipt_refs      {r['payload_receipt_refs']:>8,}")
    print(f"  trajectories              {r['trajectories']:>8,}  "
          f"(largest {r['largest_trajectory']:,} receipts)")
    print(f"  relationships             {r['relationships']:>8,}")
    if r["chain_entries"]:
        print(f"  chain entries             {r['chain_entries']:>8,}  "
              f"({r['chain_remaining']:,} not yet processed)")
    if r["last_processed_at"]:
        print(f"  last processed at         {r['last_processed_at']}")

    rc = 0
    print()
    if r["silently_skipped"]:
        print(f"  SILENTLY SKIPPED: {r['silently_skipped']:,} entries.")
        print("  The high-water mark advanced past entries that were never linked to any")
        print("  object. These are the catchup's swallowed failures. They will never be")
        print("  revisited: the HWM says they are done. Rebuilding the ontology from the")
        print("  chain is the recovery -- the database is disposable by design")
        print("  (schema-v1.sql, KEEL §II.13 P5).")
        rc = 1
    else:
        print("  No skipped entries: every entry the HWM claims is linked to an object.")

    if r["view_disagrees_with_itself"]:
        d = r["view_disagrees_with_itself"]
        print(f"  VIEW INCONSISTENT: object_receipts and payload receipt_refs differ by {d:,}.")
        print("  These are written in the same function and should never diverge. A"
              " non-zero")
        print("  value here is a bug in process_entry, not a data-loss event.")
        rc = 1

    if r["largest_trajectory"] and r["largest_trajectory"] > 250:
        print(f"  CADENCE CAP EXCEEDED: largest trajectory holds "
              f"{r['largest_trajectory']:,} receipts, over the 250 cap.")
        print("  trajectory_receipt_cap is vetoed by an explicit operator continuity")
        print("  marker (boundary.rs: s5 != Some(-1.0)). Payload rewrite cost grows with")
        print("  the square of this number.")
        rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
