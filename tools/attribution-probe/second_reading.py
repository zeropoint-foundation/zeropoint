#!/usr/bin/env python3
"""Second reading for HOST-ATTRIBUTION-CLOSURE-2026-08 §8.

EXPERIMENT ARTIFACT, NOT SUBSTRATE CODE.

WHY v2 EXISTS — three defects the first reading exposed in itself
    1. RACE. v1 called `ps` twice and joined on pid. A process that exited
       between the calls appeared in the first and not the second, so it
       lost its path and fell into a bucket named `kernel-or-pathless`.
       That bucket took 912 of 1718 records (53%), and 810 records were
       seen in exactly one sample. The overlap is not coincidence: v1 was
       systematically blind to precisely the short-lived processes the
       measure exists to catch, and it labelled them with a name that
       reads as benign. A reassuring bucket name concealing a measurement
       failure is worse than an error, because it does not look like one.
       FIX: one `ps` call. `comm` is the last field, so the path is simply
       everything after token 7. The two-call join was never necessary.

    2. VERDICT AT n=2. v1 printed "DOMINATED — this is not a general
       attribution measure and should be renamed" from two data points,
       where the largest of two necessarily holds 50%. FIX: the dominance
       test is gated on MIN_N and otherwise reports insufficient sample.

    3. LOCATION IS NOT PROVENANCE. v1 attributed by path prefix, so
       `/Users/` vouched for anything in the operator's home directory.
       §4.2 requires attribution to name executable identity, what
       authorized it, and expected behaviour class. A prefix supplies
       none of those. FIX: code signature becomes the primary key, and
       BOTH classifications are reported side by side so the difference
       between attribution-by-location and attribution-by-signature is
       visible as a number rather than asserted.

    v1's two genuine findings survived all three defects and are the
    reason this is worth re-running: `com.docker.vmnetd`, a privileged
    root helper, and `/usr/local/bin/zp` — the substrate could not
    account for itself.

STILL DELIBERATELY ABSENT
    No closure percentage is computed anywhere. `ps -o args=` is never
    invoked; argv is not read (§III.24 Layer 3). Nothing is written to
    the chain.

USAGE
    python3 second_reading.py                     # until discovery goes dry
    python3 second_reading.py --json reading-02.json
    python3 second_reading.py --no-dry --window 1800

    codesign runs once per distinct executable AFTER sampling ends, so it
    does not perturb the window. Expect ~30s for a thousand executables.
"""

import argparse
import collections
import os
import json
import signal
import subprocess
import sys
import time

MIN_N = 20          # below this, the dominance test reports nothing (defect 2)

# Attribution by location. RETAINED FROM v1 DELIBERATELY, not because it is
# correct — it is not, see defect 3 — but so that v2 can measure how much
# work it was doing. First match wins.
PATH_RULES = [
    ("nix-store",   ("/nix/store/",)),
    ("homebrew",    ("/opt/homebrew/", "/usr/local/Cellar/", "/usr/local/opt/")),
    ("cryptex",     ("/System/Volumes/Preboot/Cryptexes/",)),
    ("os-baseline", ("/System/", "/usr/lib/", "/usr/libexec/", "/usr/sbin/",
                     "/usr/bin/", "/sbin/", "/bin/", "/kernel")),
    ("app-bundle",  ("/Applications/",)),
    ("priv-helper", ("/Library/PrivilegedHelperTools/",)),
    ("library",     ("/Library/",)),
    ("user-app",    ("/Users/",)),
    ("var",         ("/private/var/", "/var/")),
    ("opt-other",   ("/opt/",)),
    ("local-bin",   ("/usr/local/",)),
]
UNACCOUNTED = "unaccounted"
UNRESOLVED = "path-unresolved"      # renamed from v1's `kernel-or-pathless`


def classify_path(path):
    if not path or not path.startswith("/"):
        return UNRESOLVED
    for name, prefixes in PATH_RULES:
        if path.startswith(prefixes):
            return name
    return UNACCOUNTED


def classify_signature(path, cache):
    """Attribution by code signature — who vouches for this binary.

    This is the provenance §4.2 asks for: a named signing authority, not a
    location on disk. Cached per path; one subprocess per distinct
    executable, run after sampling.
    """
    if path in cache:
        return cache[path]
    if not path or not path.startswith("/"):
        cache[path] = "unsigned-or-unknown"
        return cache[path]
    try:
        r = subprocess.run(["codesign", "-dv", "--verbose=2", path],
                           capture_output=True, text=True, timeout=10)
        txt = (r.stderr or "") + (r.stdout or "")
    except (subprocess.SubprocessError, OSError):
        cache[path] = "codesign-unavailable"
        return cache[path]

    if "not signed at all" in txt:
        verdict = "UNSIGNED"
    elif "Signature=adhoc" in txt:
        verdict = "adhoc"
    else:
        auth = next((l.split("=", 1)[1].strip() for l in txt.splitlines()
                     if l.startswith("Authority=")), None)
        team = next((l.split("=", 1)[1].strip() for l in txt.splitlines()
                     if l.startswith("TeamIdentifier=")), "not set")
        if auth is None:
            verdict = "unreadable"
        elif auth == "Software Signing":
            verdict = "apple-platform"
        elif auth.startswith("Apple"):
            verdict = "apple-other"
        elif team and team != "not set":
            verdict = f"devid:{team}"
        else:
            verdict = "signed-unclassified"
    cache[path] = verdict
    return verdict


SELF_PID = os.getpid()


def sample():
    """One observation, ONE ps call. Returns {pid: (ppid, start, path)}.

    Field order matters: comm is last, so pid/ppid are tokens 0-1, lstart is
    exactly tokens 2-6, and the path is everything remaining — which may
    itself contain spaces. No join, therefore no race (defect 1).
    """
    out = {}
    try:
        txt = subprocess.run(["ps", "-axo", "pid=,ppid=,lstart=,comm="],
                             capture_output=True, text=True, timeout=15).stdout
    except (subprocess.SubprocessError, OSError) as exc:
        print(f"  ps failed: {exc}", file=sys.stderr)
        return out
    for line in txt.splitlines():
        p = line.strip().split()
        if len(p) < 8:
            continue
        # SELF-EXCLUSION (defect 4, found 2026-08-16). Without this, every
        # sample records the `ps` it just spawned. In reading-02 that was
        # 1052 of 1281 path-unresolved records — 82% of the largest category
        # in the report was the instrument observing itself, and it was
        # misdiagnosed twice: first as kernel threads, then as a join race.
        # Excluded by parentage rather than by name, so it holds regardless
        # of what the enumeration command is called.
        if p[0] == str(SELF_PID) or p[1] == str(SELF_PID):
            continue
        out[p[0]] = (p[1], " ".join(p[2:7]), " ".join(p[7:]))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--window", type=int, default=3600, help="hard ceiling seconds")
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--dry-samples", type=int, default=120,
                    help="stop after N samples with no new executable")
    ap.add_argument("--no-dry", action="store_true")
    ap.add_argument("--json", metavar="PATH")
    args = ap.parse_args()

    seen, execs = {}, set()
    samples_taken, dry_run = 0, 0
    stop = {"flag": False}
    reason = "window ceiling reached"

    def onint(_s, _f):
        stop["flag"] = True
        print("\n  interrupted — reporting on what was collected\n")
    signal.signal(signal.SIGINT, onint)

    t0 = time.time()
    print(f"sampling every {args.interval}s "
          f"{'for the full window' if args.no_dry else 'until discovery goes dry'}"
          f" (ceiling {args.window}s) — Ctrl-C to stop early")
    print("  run this while working; an idle host stops teaching quickly\n")

    while not stop["flag"] and (time.time() - t0) < args.window:
        snap = sample()
        samples_taken += 1
        now = time.time() - t0
        new = False
        for pid, (ppid, start, path) in snap.items():
            key = (pid, start)
            rec = seen.get(key)
            if rec is None:
                seen[key] = {"ppid": ppid, "path": path,
                             "bucket": classify_path(path),
                             "samples": 1, "first": now, "last": now}
                if path not in execs:
                    execs.add(path)
                    new = True
            else:
                rec["samples"] += 1
                rec["last"] = now
        dry_run = 0 if new else dry_run + 1

        if samples_taken % 15 == 0:
            unres = sum(1 for r in seen.values() if r["bucket"] == UNRESOLVED)
            unacc = sum(1 for r in seen.values() if r["bucket"] == UNACCOUNTED)
            print(f"  t+{int(now):>5}s {samples_taken:>4} samples {len(snap):>4} live "
                  f"{len(execs):>4} exec {unacc:>3} unacc {unres:>4} unresolved "
                  f"dry {dry_run:>4}/{args.dry_samples}")

        if not args.no_dry and dry_run >= args.dry_samples:
            stop["flag"] = True
            reason = f"saturated — {args.dry_samples} samples, no new executable"
            print(f"\n  {reason}\n")
        else:
            time.sleep(args.interval)

    if stop["flag"] and reason == "window ceiling reached":
        reason = "interrupted by operator"
    report(seen, samples_taken, time.time() - t0, args.interval, execs, reason)

    if args.json:
        with open(args.json, "w") as fh:
            json.dump([{"pid": k[0], "start": k[1], **v} for k, v in seen.items()],
                      fh, indent=2)
        print(f"\nraw observations written to {args.json}")


def report(seen, samples_taken, elapsed, interval, execs, reason):
    if not seen:
        print("no observations collected")
        return
    ps_of = lambda r: r["samples"] * interval
    total_ps = sum(ps_of(r) for r in seen.values())
    bar = "=" * 78

    print(f"\n{bar}\nSECOND READING — HOST-ATTRIBUTION-CLOSURE-2026-08 §8\n{bar}")
    print(f"window {elapsed:.0f}s · {samples_taken} samples at {interval}s · "
          f"{len(seen)} distinct (pid,start) · {len(execs)} distinct executables · "
          f"{total_ps:.0f} process-seconds")
    print(f"stopped: {reason}")
    print("\nNO CLOSURE PERCENTAGE IS REPORTED. Evidence about the measure,")
    print("not about the host.")

    # -- 0. did the race fix work? ------------------------------------------
    unres = [r for r in seen.values() if r["bucket"] == UNRESOLVED]
    short = [r for r in seen.values() if r["samples"] <= 1]
    print(f"\n{bar}\n0. INSTRUMENT CHECK (defect 1 — the v1 race)\n{bar}")
    print(f"  path-unresolved: {len(unres)} of {len(seen)} "
          f"({100*len(unres)/len(seen):.1f}%)   [v1 45.7% self-included, 13.1% self-excluded]")
    print(f"  seen in one sample only: {len(short)} ({100*len(short)/len(seen):.1f}%)"
          f"   [v1 saw 47.1%]")
    print("  If path-unresolved is still near the single-sample rate, the race")
    print("  was not the cause and the bucket is real. If it has collapsed, v1's")
    print("  largest category was an artefact of its own sampling method.")

    # -- 1. location vs signature -------------------------------------------
    print(f"\n{bar}\n1. ATTRIBUTION BY LOCATION (v1's method, retained to measure it)\n{bar}")
    byb, psb = collections.Counter(), collections.Counter()
    for r in seen.values():
        byb[r["bucket"]] += 1
        psb[r["bucket"]] += ps_of(r)
    print(f"{'source':<22}{'distinct':>9}{'proc-sec':>12}{'% proc-sec':>13}")
    for b, n in byb.most_common():
        print(f"{b:<22}{n:>9}{psb[b]:>12.0f}{100*psb[b]/total_ps:>12.1f}%")

    print(f"\n{bar}\n2. ATTRIBUTION BY SIGNATURE (§4.2 provenance)\n{bar}")
    paths = sorted({r["path"] for r in seen.values() if r["path"]})
    print(f"  running codesign on {len(paths)} distinct executables...", flush=True)
    cache = {}
    for i, p in enumerate(paths, 1):
        classify_signature(p, cache)
        if i % 200 == 0:
            print(f"    {i}/{len(paths)}", flush=True)
    bys, pss = collections.Counter(), collections.Counter()
    for r in seen.values():
        v = cache.get(r["path"], "unsigned-or-unknown")
        bys[v] += 1
        pss[v] += ps_of(r)
    print(f"\n{'authority':<28}{'distinct':>9}{'proc-sec':>12}{'% proc-sec':>13}")
    for v, n in bys.most_common(15):
        print(f"{v:<28}{n:>9}{pss[v]:>12.0f}{100*pss[v]/total_ps:>12.1f}%")

    # -- 3. the disagreement is the finding ---------------------------------
    print(f"\n{bar}\n3. WHERE LOCATION AND SIGNATURE DISAGREE\n{bar}")
    lied = [(r["path"], r["bucket"], cache.get(r["path"]))
            for r in seen.values()
            if r["bucket"] not in (UNACCOUNTED, UNRESOLVED)
            and cache.get(r["path"]) in ("UNSIGNED", "adhoc", "unreadable",
                                         "signed-unclassified")]
    uniq = sorted(set(lied))
    print(f"  {len(uniq)} distinct executables that location attributed but")
    print(f"  signature does not vouch for. These are the ones v1 hid.")
    for path, loc, sig in uniq[:25]:
        print(f"    {sig:<20} was {loc:<14} {path}")
    if len(uniq) > 25:
        print(f"    ... and {len(uniq)-25} more")

    # -- 4. dominance, gated ------------------------------------------------
    unacc = [r for r in seen.values() if r["bucket"] == UNACCOUNTED]
    print(f"\n{bar}\n4. IS UNACCOUNTED ONE SHAPE? (defect 2 — gated at n={MIN_N})\n{bar}")
    if not unacc:
        print("  ZERO unaccounted under the location ruleset. Read section 3 instead:")
        print("  with a permissive ruleset, zero here is a statement about the rules.")
    else:
        ue, up = collections.Counter(), collections.Counter()
        for r in unacc:
            ue[r["path"] or "(unresolved)"] += 1
            up[r["path"] or "(unresolved)"] += ps_of(r)
        tot = sum(up.values())
        print(f"  {len(unacc)} distinct unaccounted · {len(ue)} executables · {tot:.0f} proc-sec")
        if len(ue) < MIN_N:
            print(f"  >> INSUFFICIENT SAMPLE ({len(ue)} < {MIN_N}). No dominance verdict.")
            print(f"  >> v1 reported DOMINATED from n=2, where the larger of two")
            print(f"  >> necessarily holds 50%. That verdict was arithmetic, not evidence.")
        else:
            top = 100 * up.most_common(1)[0][1] / tot
            print(f"  largest executable holds {top:.1f}% of unaccounted proc-seconds")
            print("  >> DOMINATED — rename the measure for that shape." if top >= 50
                  else "  >> HETEROGENEOUS — the general formulation survives.")
        print(f"\n  {'proc-sec':>9}{'count':>7}  {'signature':<20} executable")
        for path, p in up.most_common(25):
            print(f"  {p:>9.0f}{ue[path]:>7}  {str(cache.get(path,'?')):<20} {path}")

    print(f"\n{bar}\nNEXT: record BOTH classifications in DELIBERATION-LOG, with the")
    print("change that produced them (v1 -> v2: race fixed, codesign added,")
    print("dominance gated). Per TRIAGE-FOR-COHERENCE the delta is the evidence.")
    print(bar)


if __name__ == "__main__":
    main()
