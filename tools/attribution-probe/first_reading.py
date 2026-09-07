#!/usr/bin/env python3
"""First reading for HOST-ATTRIBUTION-CLOSURE-2026-08 §8.

EXPERIMENT ARTIFACT, NOT SUBSTRATE CODE. This exists to answer one question
and should be deleted or deliberately promoted afterwards. It is not a
detector, it emits no receipts, and nothing should come to depend on it.

WHAT IT ANSWERS
    Is unaccounted execution on this host heterogeneous, or is it one shape
    wearing many PIDs? Precedent: 498 of 656 corpus_to_chain defects turned
    out to be a single class, which meant the ranking rule governed a
    minority and the bulk was one measurable problem. If unaccounted
    execution is similarly dominated, host attribution closure is not a
    general measure and should be renamed for what it actually tracks.

WHAT IT DELIBERATELY DOES NOT DO
    It does not print a closure percentage. Per TRIAGE-FOR-COHERENCE, a new
    measure's first reading is evidence about the measure, not about the
    system; a percentage now would be read as a system fact. It prints the
    distribution. The percentage is not computed anywhere in this file.

    It does not read argv. §III.24 Layer 3 names command-line secret
    patterns as scrub-before-anchoring, and attribution keys on executable
    identity and authorization provenance, not arguments. `ps -o args=` is
    never invoked. This is a design constraint, not an oversight.

    It does not write to the chain, does not touch the repo, and needs no
    privileges beyond what `ps` already gives the calling user.

USAGE
    python3 first_reading.py                      # runs until discovery goes dry
    python3 first_reading.py --json out.json      # same, keeping raw observations
    python3 first_reading.py --dry-samples 200    # demand a longer quiet run
    python3 first_reading.py --no-dry --window 60 # fixed short window instead

    Ctrl-C at any point reports on what was collected so far.

STOPPING
    Not by clock. The question here is compositional — is unaccounted
    execution one shape or many — so the reading is complete when the host
    stops showing new *kinds* of executable, not when a timer expires. The
    default stops after --dry-samples consecutive samples with no
    previously-unseen executable path, with --window as a hard ceiling.

    An idle hour is worth less than five busy minutes. Run it while working
    — a build, a browser session, opening applications — because the
    executables that only appear under load are the ones a snapshot misses
    and the ones most likely to be unaccounted.

PLATFORM
    macOS (BSD ps). The path-prefix rules in ATTRIBUTION_RULES are macOS
    specific and are the part most likely to be wrong; they are the
    hypothesis under test, not settled fact.
"""

import argparse
import collections
import json
import signal
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# The closed set.
#
# HOST-ATTRIBUTION-CLOSURE §4.1 requires attribution categories to be a closed
# set, because one free-text or `allowed:unknown` bucket makes attributing
# cheaper than understanding. This list IS that closed set for the experiment.
# Adding a row is the ceremony. Order matters: first match wins, so the most
# specific prefixes come first.
#
# These are *candidate attribution sources* — "who would vouch for this" —
# not attributions. A real attribution additionally requires the authorizing
# delegation and an expected behavior class, neither of which exists yet.
# ---------------------------------------------------------------------------
ATTRIBUTION_RULES = [
    ("nix-store",      ("/nix/store/",)),
    ("homebrew",       ("/opt/homebrew/", "/usr/local/Cellar/", "/usr/local/opt/")),
    ("os-baseline",    ("/System/", "/usr/lib/", "/usr/libexec/", "/usr/sbin/",
                        "/usr/bin/", "/sbin/", "/bin/", "/kernel")),
    ("cryptex",        ("/System/Volumes/Preboot/Cryptexes/",)),
    ("app-bundle",     ("/Applications/",)),
    ("user-app",       ("/Users/",)),
    ("private-var",    ("/private/var/", "/var/")),
    ("opt-other",      ("/opt/",)),
]
UNACCOUNTED = "unaccounted"

# Kernel threads and anything ps reports without a resolvable path. Reported
# separately rather than folded into `unaccounted`, because conflating "the
# kernel" with "an unexplained binary" would be the measure's first lie.
KERNEL_LIKE = "kernel-or-pathless"


def classify(path):
    if not path or not path.startswith("/"):
        return KERNEL_LIKE
    for name, prefixes in ATTRIBUTION_RULES:
        if path.startswith(prefixes):
            return name
    return UNACCOUNTED


def sample():
    """One observation. Returns {pid: (ppid, start, path)}.

    Two ps calls because both lstart and the executable path can contain
    spaces, and BSD ps has no field delimiter. lstart is a fixed 5-token
    date; the path is everything after the pid. Joining on pid is exact
    within a single instant.
    """
    out = {}
    try:
        a = subprocess.run(["ps", "-axo", "pid=,ppid=,lstart="],
                           capture_output=True, text=True, timeout=15).stdout
        b = subprocess.run(["ps", "-axo", "pid=,comm="],
                           capture_output=True, text=True, timeout=15).stdout
    except (subprocess.SubprocessError, OSError) as exc:
        print(f"  ps failed: {exc}", file=sys.stderr)
        return out

    paths = {}
    for line in b.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            paths[parts[0]] = parts[1]

    for line in a.splitlines():
        parts = line.strip().split()
        if len(parts) < 3:
            continue
        pid, ppid = parts[0], parts[1]
        start = " ".join(parts[2:7])          # lstart is exactly 5 tokens
        out[pid] = (ppid, start, paths.get(pid, ""))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--window", type=int, default=3600,
                    help="hard ceiling in seconds (default 3600 = one hour)")
    ap.add_argument("--interval", type=float, default=2.0, help="sampling seconds (default 2)")
    ap.add_argument("--dry-samples", type=int, default=120,
                    help="stop after N consecutive samples with no new executable "
                         "(default 120 = 4 min at the default interval)")
    ap.add_argument("--no-dry", action="store_true",
                    help="ignore saturation; run the full --window")
    ap.add_argument("--json", metavar="PATH", help="write raw observation dump here")
    args = ap.parse_args()

    # Identity key is (pid, start_time) — pid alone is reused by the OS, and
    # reuse would silently merge two different processes into one long life.
    seen = {}                      # key -> {ppid, path, bucket, samples, first, last}
    execs = set()                  # distinct executable paths ever observed
    samples_taken = 0
    dry_run = 0                    # consecutive samples with no new executable
    stop = {"flag": False}
    reason = "window ceiling reached"

    def onint(_sig, _frm):
        stop["flag"] = True
        print("\n  interrupted — reporting on what was collected\n")
    signal.signal(signal.SIGINT, onint)

    t0 = time.time()
    if args.no_dry:
        print(f"sampling every {args.interval}s for the full {args.window}s "
              f"— Ctrl-C to stop early\n")
    else:
        print(f"sampling every {args.interval}s until discovery goes dry "
              f"({args.dry_samples} consecutive samples with no new executable), "
              f"ceiling {args.window}s — Ctrl-C to stop early")
        print("  run this while working; an idle host stops teaching quickly\n")

    while not stop["flag"] and (time.time() - t0) < args.window:
        snap = sample()
        samples_taken += 1
        now = time.time() - t0
        found_new = False
        for pid, (ppid, start, path) in snap.items():
            key = (pid, start)
            rec = seen.get(key)
            if rec is None:
                seen[key] = {"ppid": ppid, "path": path, "bucket": classify(path),
                             "samples": 1, "first": now, "last": now}
                if path not in execs:
                    execs.add(path)
                    found_new = True
            else:
                rec["samples"] += 1
                rec["last"] = now

        dry_run = 0 if found_new else dry_run + 1

        if samples_taken % 15 == 0:
            unacc = sum(1 for r in seen.values() if r["bucket"] == UNACCOUNTED)
            print(f"  t+{int(now):>5}s  {samples_taken:>4} samples  "
                  f"{len(snap):>4} live  {len(execs):>4} distinct-exec  "
                  f"{unacc:>4} unaccounted  dry {dry_run:>4}/{args.dry_samples}")

        if not args.no_dry and dry_run >= args.dry_samples:
            stop["flag"] = True
            reason = (f"saturated — {args.dry_samples} consecutive samples "
                      f"with no previously-unseen executable")
            print(f"\n  {reason}\n")
        else:
            time.sleep(args.interval)

    elapsed = time.time() - t0
    if stop["flag"] and reason == "window ceiling reached":
        reason = "interrupted by operator"
    report(seen, samples_taken, elapsed, args.interval, len(execs), reason)

    if args.json:
        with open(args.json, "w") as fh:
            json.dump([{"pid": k[0], "start": k[1], **v} for k, v in seen.items()],
                      fh, indent=2)
        print(f"\nraw observations written to {args.json}")


def report(seen, samples_taken, elapsed, interval, n_execs=None, reason=""):
    if not seen:
        print("no observations collected")
        return

    def psecs(rec):
        return rec["samples"] * interval

    total_ps = sum(psecs(r) for r in seen.values())
    bar = "=" * 78

    print(f"\n{bar}\nFIRST READING — HOST-ATTRIBUTION-CLOSURE-2026-08 §8")
    print(f"{bar}")
    print(f"window {elapsed:.0f}s · {samples_taken} samples at {interval}s · "
          f"{len(seen)} distinct (pid,start) · "
          f"{n_execs if n_execs is not None else '?'} distinct executables · "
          f"{total_ps:.0f} process-seconds observed")
    if reason:
        print(f"stopped: {reason}")
        if reason.startswith("window ceiling"):
            print("  NOTE: hit the ceiling without saturating. Discovery was still")
            print("  producing new executables when this stopped, so the composition")
            print("  below is a floor, not a description. Re-run with a higher --window.")
    print("\nNO CLOSURE PERCENTAGE IS REPORTED. This reading is evidence about")
    print("the measure, not about the host. Read the shape, not a score.")

    # --- distribution by candidate attribution source -----------------------
    by_bucket = collections.Counter()
    ps_bucket = collections.Counter()
    for r in seen.values():
        by_bucket[r["bucket"]] += 1
        ps_bucket[r["bucket"]] += psecs(r)

    print(f"\n{bar}\n1. BY CANDIDATE ATTRIBUTION SOURCE (the closed set)\n{bar}")
    print(f"{'source':<22}{'distinct':>9}{'proc-sec':>12}{'% of proc-sec':>15}")
    for b, n in by_bucket.most_common():
        print(f"{b:<22}{n:>9}{ps_bucket[b]:>12.0f}{100*ps_bucket[b]/total_ps:>14.1f}%")

    # --- the question the experiment exists to answer -----------------------
    unacc = {k: r for k, r in seen.items() if r["bucket"] == UNACCOUNTED}
    print(f"\n{bar}\n2. IS UNACCOUNTED ONE SHAPE?  (the disconfirming question)\n{bar}")
    if not unacc:
        print("  ZERO unaccounted processes observed.")
        print("  This REFUTES §2's dynamic on this host under this ruleset:")
        print("  ungoverned accretion is not occurring, or ATTRIBUTION_RULES is")
        print("  too generous. Check rule 4 below before believing the former.")
    else:
        u_exec = collections.Counter()
        u_ps = collections.Counter()
        for r in unacc.values():
            u_exec[r["path"] or "(pathless)"] += 1
            u_ps[r["path"] or "(pathless)"] += psecs(r)
        tot_u = sum(u_ps.values())
        top_share = 100 * u_ps.most_common(1)[0][1] / tot_u if tot_u else 0
        print(f"  {len(unacc)} distinct unaccounted · {len(u_exec)} distinct executables "
              f"· {tot_u:.0f} proc-sec")
        print(f"  largest single executable holds {top_share:.1f}% of unaccounted proc-seconds")
        if top_share >= 50:
            print("  >> DOMINATED. One shape holds the majority. Per §8 this is not a")
            print("  >> general attribution measure and should be renamed for that shape.")
        else:
            print("  >> HETEROGENEOUS. No single executable dominates; the general")
            print("  >> formulation survives this reading.")
        print(f"\n  {'proc-sec':>9}{'count':>7}  executable")
        for path, ps in u_ps.most_common(20):
            print(f"  {ps:>9.0f}{u_exec[path]:>7}  {path}")

    # --- lifetime shape -----------------------------------------------------
    short = [r for r in seen.values() if r["samples"] <= 1]
    print(f"\n{bar}\n3. LIFETIME SHAPE (why the measure must be windowed)\n{bar}")
    print(f"  seen in exactly one sample: {len(short)} of {len(seen)} "
          f"({100*len(short)/len(seen):.1f}%)")
    print(f"  These are invisible to any point-in-time snapshot. A single `ps`")
    print(f"  would have missed {len(short)} processes entirely.")
    s_unacc = sum(1 for r in short if r["bucket"] == UNACCOUNTED)
    print(f"  of those, unaccounted: {s_unacc}")

    # --- parentage ----------------------------------------------------------
    print(f"\n{bar}\n4. TOP PARENTS OF UNACCOUNTED (is parent-attribution viable?)\n{bar}")
    if unacc:
        paths_by_pid = {k[0]: r["path"] for k, r in seen.items()}
        par = collections.Counter()
        for r in unacc.values():
            par[paths_by_pid.get(r["ppid"], f"(ppid {r['ppid']})")] += 1
        for p, n in par.most_common(10):
            print(f"  {n:>5}  {p}")
        print("\n  If these parents are themselves well-attributed, a parent-attribution")
        print("  rule would collapse most of the unaccounted set — which §6 warns is")
        print("  the liberal-attribution cheat. Decide deliberately, not by default.")
    else:
        print("  n/a — nothing unaccounted")

    print(f"\n{bar}")
    print("NEXT: record the distribution in DELIBERATION-LOG as the first reading,")
    print("with the change that produced it (none — first run). Do not publish a")
    print("closure figure until the ruleset above has survived review.")
    print(bar)


if __name__ == "__main__":
    main()
