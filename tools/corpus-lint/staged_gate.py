#!/usr/bin/env python3
"""Fail a commit on corpus-lint defects in the documents that commit touches.

Called by `.githooks/pre-commit`. Reads staged paths on stdin, runs
`corpus_lint.py --json` over the whole tree, and reports only the defects whose
path is staged.

# Why scoped rather than --strict (2026-08-14)

`corpus_lint.py --strict` exits 1 if *any* defect exists anywhere. The corpus
carries 15-16 at any given time — dangling `doc-path` citations in 2026-05
documents, unindexed post-convention drafts — none of which the author of an
unrelated commit can or should fix on the spot. A gate in that shape blocks
every commit on somebody else's debt, and `.githooks/pre-commit` already states
what happens next: the hook gets disabled within a week, and a disabled hook is
worse than none because the repo still contains one.

Scoping to the staged set inverts that. The only thing that can block your
commit is a defect in a file you are committing, which is the one class you are
positioned to fix while you are already there. The corpus-wide count still
prints, as a measurement nobody is required to act on.

The motivating case is `index-missing`: a document authored after the index's
2026-07-10 establishment date and not listed in it. Eight such documents exist
as of this writing, every one of them added by a commit that could have caught
it in the second it took to add an index line. That defect class is cheap at
the moment of authorship and expensive later, when the doc has to be re-read by
someone reconstructing what it was for.

# Cost

One `corpus_lint.py` run, ~7s after the 2026-08-14 walk-pruning fix; it was
40s+ before, which is why this gate was not worth proposing until now. The hook
skips it entirely when no `docs/**.md` is staged.
"""
import json, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def main():
    staged = {l.strip() for l in sys.stdin if l.strip()}
    if not staged:
        return 0

    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools/corpus-lint/corpus_lint.py"), str(ROOT), "--json"],
        capture_output=True, text=True)
    if proc.returncode != 0 and not proc.stdout:
        print("pre-commit: corpus-lint failed to run — this is a gap, not a pass.")
        print(proc.stderr.strip()[:2000])
        return 0                      # never block on the linter's own breakage

    findings = json.loads(proc.stdout)

    def rel(p):
        p = str(p)
        try:
            return str(Path(p).resolve().relative_to(ROOT))
        except ValueError:
            return p.lstrip("./")

    defects = [f for f in findings if f["kind"] == "defect"]
    mine = [f for f in defects if rel(f["path"]) in staged]

    total = len(defects)
    print(f"pre-commit: corpus-lint — {total} defect(s) corpus-wide, "
          f"{len(mine)} in this commit's documents.")

    if not mine:
        return 0

    print("")
    for f in mine:
        loc = f"{rel(f['path'])}:{f['line']}" if f.get("line") else rel(f["path"])
        print(f"  [{f['check']}] {loc}")
        print(f"    {f['msg']}")
    print("")
    print("pre-commit: these are in files you are committing. Commit aborted.")
    print("")
    print("The common one is 'index-missing' — add the document to")
    print("docs/CANONICAL-CORPUS-INDEX-2026-07.md. A dangling 'doc-path' or")
    print("'crossref' means a citation names something that is not there;")
    print("fix the citation, or mark the target as not yet written, which the")
    print("linter honours deliberately.")
    print("")
    print("To commit anyway: git commit --no-verify")
    print("")
    return 1

if __name__ == "__main__":
    sys.exit(main())
