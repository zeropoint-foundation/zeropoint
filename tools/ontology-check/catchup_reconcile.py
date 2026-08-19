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

Read-only, and safe to run *during* the catchup rather than only after it.
That matters because the only other signal that catchup has finished is a log
line, and the operator running this may have no way to see the log.

    python3 tools/ontology-check/catchup_reconcile.py            # status now
    python3 tools/ontology-check/catchup_reconcile.py --watch    # until done
    python3 tools/ontology-check/catchup_reconcile.py --json
"""
import argparse, json, os, pathlib, re, sqlite3, sys, time



def resolve_data_dir(explicit=None):
    """Find the data directory the way the binary does, and say which one won.

    The first version of this script defaulted to ~/.zeropoint, which is not
    where anything lives. That failure mode is nasty: a wrong path reports
    "no ontology database" indefinitely, which is indistinguishable from the
    Cartographer never having started, so the operator concludes the flag did
    not take and restarts a server that was working fine.

    Precedence mirrors zp-config (schema.rs zp_home + resolve.rs):

        ZP_DATA_DIR                       explicit override
        <zp_home>/data                    where zp_home is ZP_HOME, else
                                          ~/ZeroPoint
        data_dir from <zp_home>/config.toml, if set there

    Returns (path, how_it_was_chosen) so the caller can print it. Printing it
    is the point: a wrong guess must be visible in the output rather than
    silently producing an empty answer.
    """
    if explicit:
        return pathlib.Path(explicit).expanduser(), "--data-dir"

    if os.environ.get("ZP_DATA_DIR"):
        return pathlib.Path(os.environ["ZP_DATA_DIR"]).expanduser(), "ZP_DATA_DIR"

    zp_home = pathlib.Path(os.environ.get("ZP_HOME") or
                           pathlib.Path.home() / "ZeroPoint").expanduser()

    cfg = zp_home / "config.toml"
    if cfg.exists():
        # Deliberately a regex rather than a TOML parse: this script must run
        # on a stock python3 with no third-party imports, and 3.10 has no
        # tomllib. A data_dir set some exotic way falls through to the default
        # below, which is reported, so the failure is legible.
        try:
            m = re.search(r'^\s*data[_.]?dir\s*=\s*["\']([^"\']+)["\']',
                          cfg.read_text(), re.M | re.I)
            if m:
                return pathlib.Path(m.group(1)).expanduser(), str(cfg)
        except OSError:
            pass

    return (zp_home / "data",
            "ZP_HOME/data" if os.environ.get("ZP_HOME") else "default ~/ZeroPoint/data")


def ro(path):
    """Open read-only against a database that may be actively written.

    Deliberately NOT `immutable=1`. The first version of this script used it,
    on the reasoning that read-only plus immutable is maximally safe. It is
    the opposite: `immutable` is a promise to SQLite that the file cannot
    change, which licenses it to skip locking and cache pages indefinitely.
    Point that at a database the Cartographer is mid-catchup on and the reads
    are undefined -- not merely stale. The whole purpose of this script is to
    be run while that catchup is happening.

    `mode=ro` takes the normal read path and observes a consistent snapshot of
    a live writer. If the database is in WAL mode and its sidecar files are
    not readable, SQLite refuses to open rather than lying, and that refusal
    is surfaced instead of being swallowed.
    """
    p = pathlib.Path(path)
    if not p.exists():
        return None
    try:
        return sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error as e:
        print(f"could not open {p} read-only: {e}", file=sys.stderr)
        return None


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


def phase(r, previous_hwm=None):
    """What state is the catchup in, judged from the database alone.

    The log is not consulted and does not need to be. `last_processed_sequence`
    is the Cartographer's own cursor, written as it goes; the chain's max rowid
    is the target. Their relationship, plus whether the cursor moved since the
    last sample, says everything the log line would have.

    STALLED is reported rather than folded into RUNNING because they look
    identical in a single sample and are completely different situations: one
    needs patience, the other needs the process checked.
    """
    hwm, total = r.get("hwm_claims_processed") or 0, r.get("chain_entries")
    if not hwm and not r.get("trajectories"):
        return "NOT STARTED", "ontology exists but nothing has been processed yet"
    if total is None:
        return "UNKNOWN", "chain database unreadable — cannot tell how much is left"
    if hwm >= total:
        return "COMPLETE", f"cursor has reached the end of the chain ({hwm:,})"
    if previous_hwm is None:
        return "RUNNING", f"{total - hwm:,} entries still ahead of the cursor"
    if hwm > previous_hwm:
        return "RUNNING", f"cursor advanced {hwm - previous_hwm:,} since last sample"
    return "STALLED", ("cursor has not moved between samples with "
                       f"{total - hwm:,} entries remaining")


def watch(ontology, audit, interval, quiet_samples=3):
    """Poll until the cursor reaches the chain end, or stops moving.

    Exits on COMPLETE, or after `quiet_samples` consecutive STALLED readings.
    A single stalled sample is not enough: catchup pauses naturally while a
    batch of 500 is processed without touching the cursor, and calling that a
    stall would cry wolf on every run.
    """
    prev, stalled, started, seen_max = None, 0, None, 0
    while True:
        r = reconcile(ontology, audit)
        if "error" in r:
            print(r["error"])
            return 2
        st, why = phase(r, prev)
        hwm = r["hwm_claims_processed"] or 0
        total = r["chain_entries"]
        if started is None and hwm:
            started = (time.time(), hwm)
        rate = eta = None
        if started and hwm > started[1]:
            elapsed = time.time() - started[0]
            rate = (hwm - started[1]) / max(elapsed, 0.001)
            if total and rate > 0:
                eta = (total - hwm) / rate
        bar = ""
        if total:
            pct = min(hwm / total, 1.0)
            filled = int(pct * 28)
            bar = f" [{'#' * filled}{'.' * (28 - filled)}] {pct * 100:5.1f}%"
        line = f"{st:<10} {hwm:>8,}/{total:,}" if total else f"{st:<10} {hwm:>8,}"
        if rate:
            line += f"  {rate:6.0f}/s"
        if eta and st == "RUNNING":
            line += f"  eta {int(eta // 60)}m{int(eta % 60):02d}s"
        print(line + bar, flush=True)

        if st == "COMPLETE":
            print()
            return report(r, known=(st, why))
        stalled = stalled + 1 if st == "STALLED" else 0
        if stalled >= quiet_samples:
            print(f"\ncursor unchanged across {quiet_samples} samples "
                  f"({interval}s apart). Catchup is not progressing.")
            print("Check the server is running and look for "
                  "'Cartographer catchup failed' or 'task exiting'.")
            print()
            return report(r, known=("STALLED", why)) or 3
        prev, seen_max = hwm, max(seen_max, hwm)
        time.sleep(interval)


def report(r, known=None):
    """Print the reconciliation. Returns the exit code.

    `known` carries a status the caller established across samples, which a
    single snapshot cannot: STALLED and RUNNING are indistinguishable from one
    reading. Without it the watcher printed "not progressing" and then, three
    lines later, "still in progress" — the same state described two
    contradictory ways because the second description had less information
    than the first.
    """
    st, why = known if known else phase(r)
    print("Cartographer catchup reconciliation")
    print(f"  status                    {st}  — {why}")
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
    if st == "RUNNING" or st == "NOT STARTED":
        # Reconciliation figures are meaningless mid-run: the cursor is ahead
        # of the links by design while a batch is in flight. Say so rather
        # than printing a skip count that is an artifact of the timing.
        print("  Catchup is still in progress. Skip and consistency checks are not")
        print("  meaningful until the cursor stops moving — re-run with --watch.")
        return 0
    if st == "STALLED":
        # The counts below are real, but they describe a partial ontology. The
        # gap between the cursor and the chain is unprocessed, not skipped:
        # nothing has claimed it is done.
        print(f"  Stopped short: {r['chain_remaining']:,} entries were never reached.")
        print("  This is unprocessed, not skipped — the cursor never claimed them, so a")
        print("  restart resumes from here rather than losing them.")
        rc = 3

    # From here the checks only ever raise the exit code. `rc = 1` would
    # silently downgrade the stall reported above, which is the more urgent
    # of the two conditions.
    if r["silently_skipped"]:
        print(f"  SILENTLY SKIPPED: {r['silently_skipped']:,} entries.")
        print("  The high-water mark advanced past entries that were never linked to any")
        print("  object. These are the catchup's swallowed failures. They will never be")
        print("  revisited: the HWM says they are done. Rebuilding the ontology from the")
        print("  chain is the recovery — the database is disposable by design")
        print("  (schema-v1.sql, KEEL §II.13 P5).")
        rc = max(rc, 1)
    else:
        print("  No skipped entries: every entry the HWM claims is linked to an object.")

    if r["view_disagrees_with_itself"]:
        d = r["view_disagrees_with_itself"]
        print(f"  VIEW INCONSISTENT: object_receipts and payload receipt_refs differ by {d:,}.")
        print("  These are written in the same function and should never diverge. A"
              " non-zero")
        print("  value here is a bug in process_entry, not a data-loss event.")
        rc = max(rc, 1)

    if r["largest_trajectory"] and r["largest_trajectory"] > 250:
        print(f"  CADENCE CAP EXCEEDED: largest trajectory holds "
              f"{r['largest_trajectory']:,} receipts, over the 250 cap.")
        print("  trajectory_receipt_cap is vetoed by an explicit operator continuity")
        print("  marker (boundary.rs: s5 != Some(-1.0)). Payload rewrite cost grows with")
        print("  the square of this number.")
        rc = max(rc, 1)
    return rc


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default=None,
                    help="directory holding ontology.db and audit.db "
                         "(default: resolved like the binary — ZP_DATA_DIR, "
                         "then ZP_HOME/data, then ~/ZeroPoint/data)")
    ap.add_argument("--ontology", default=None)
    ap.add_argument("--audit", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--watch", action="store_true",
                    help="poll until the cursor reaches the end of the chain, or stops moving")
    ap.add_argument("--interval", type=float, default=5.0,
                    help="seconds between samples in --watch mode (default 5)")
    args = ap.parse_args()

    d, how = resolve_data_dir(args.data_dir)
    onto = pathlib.Path(args.ontology) if args.ontology else d / "ontology.db"
    audit = pathlib.Path(args.audit) if args.audit else d / "audit.db"
    if not args.json:
        print(f"data dir: {d}  [{how}]")
        if not d.exists():
            print(f"  that directory does not exist. Override with --data-dir, "
                  f"or set ZP_DATA_DIR to match the server.")

    if args.watch:
        # The ontology file does not exist until the Cartographer opens it, so
        # waiting for it is part of watching rather than an error. Otherwise
        # starting the watcher before the server loses the race every time.
        waited = 0.0
        while not pathlib.Path(onto).exists():
            if waited == 0:
                print(f"waiting for {onto} to appear "
                      "(the Cartographer creates it on first open)...", flush=True)
            time.sleep(args.interval)
            waited += args.interval
            if waited >= 120:
                print("still no ontology database after 2 minutes. Is "
                      "ZP_CARTOGRAPHER_ENABLED=1 set, and did the server restart?")
                return 2
        return watch(onto, audit, args.interval)

    r = reconcile(onto, audit)
    if args.json:
        st, why = ("ERROR", r["error"]) if "error" in r else phase(r)
        # data_dir and how are in the JSON because scripts need the resolved
        # path too -- the runbook's rebuild step reads it from here rather
        # than hardcoding a directory that turned out to be wrong once already.
        print(json.dumps({**r, "status": st, "status_detail": why,
                          "data_dir": str(d), "data_dir_source": how}, indent=2))
        return 2 if "error" in r else (1 if r.get("silently_skipped") else 0)
    if "error" in r:
        print(r["error"])
        return 2
    return report(r)


if __name__ == "__main__":
    sys.exit(main())
